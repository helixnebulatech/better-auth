import type { GenericEndpointContext } from "@better-auth/core";
import { BetterAuthError } from "@better-auth/core/error";
import type { SchemaClient, Scope } from "@better-auth/oauth-provider";
import { oauthProvider } from "@better-auth/oauth-provider";
import { jwt } from "better-auth/plugins/jwt";
import { getTestInstance } from "better-auth/test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createCimdClientDiscovery, createCimdMetadataResolver } from "./index";
import type { CimdMetadataResolver, CimdOptions } from "./types";

let portSequence = 0;

const RICH_PROVIDER_OPTIONS = {
	pairwiseSecret: "a-test-pairwise-secret-of-length",
	pushedAuthorizationRequests: { enabled: true },
};

function deferred<T>() {
	let resolve!: (value: T) => void;
	const promise = new Promise<T>((res) => {
		resolve = res;
	});
	return { promise, resolve };
}

function sampleMetadata(clientId: string, extra: Record<string, unknown> = {}) {
	return {
		client_id: clientId,
		client_name: "Test Client",
		redirect_uris: ["https://client.example/callback"],
		token_endpoint_auth_method: "none",
		grant_types: ["authorization_code"],
		response_types: ["code"],
		...extra,
	};
}

function documentResponse(body: unknown, cacheControl = "max-age=3600") {
	return Response.json(body, {
		headers: { "cache-control": cacheControl },
	});
}

/**
 * One request's endpoint context, backed by its own database, as a runtime that
 * builds its auth instance per request has.
 */
async function createRequestContext(
	providerOptions: Record<string, unknown> = {},
) {
	portSequence += 1;
	const instance = await getTestInstance({
		baseURL: `http://localhost:${3900 + portSequence}`,
		plugins: [
			jwt(),
			oauthProvider({
				loginPage: "/login",
				consentPage: "/consent",
				scopes: ["openid"],
				...providerOptions,
			}),
		],
	});
	const context = await instance.auth.$context;
	const ctx = { context } as unknown as GenericEndpointContext;
	const readClient = async (clientId: string) =>
		(await context.adapter.findOne({
			model: "oauthClient",
			where: [{ field: "clientId", value: clientId }],
		})) as SchemaClient<Scope[]> | null;
	return { ctx, readClient };
}

describe("CIMD metadata resolver", () => {
	/**
	 * @see https://github.com/better-auth/better-auth/issues/12358
	 */
	describe("per-request persistence", () => {
		it("saves a coalesced document through each request's own context", async () => {
			const clientId = "https://coalesced.example/metadata.json";
			const barrier = deferred<Response>();
			const fetchClientMetadataResource = vi.fn(() => barrier.promise);
			const discovery = createCimdClientDiscovery({
				fetchClientMetadataResource,
			});
			const requestA = await createRequestContext();
			const requestB = await createRequestContext();

			const resolvedA = discovery.resolve(requestA.ctx, clientId, null);
			const resolvedB = discovery.resolve(requestB.ctx, clientId, null);
			await vi.waitFor(() =>
				expect(fetchClientMetadataResource).toHaveBeenCalledTimes(1),
			);
			barrier.resolve(documentResponse(sampleMetadata(clientId)));
			await Promise.all([resolvedA, resolvedB]);

			expect(fetchClientMetadataResource).toHaveBeenCalledTimes(1);
			expect((await requestA.readClient(clientId))?.clientId).toBe(clientId);
			expect((await requestB.readClient(clientId))?.clientId).toBe(clientId);
		});

		it("does not fail a request because another request that shared its fetch could not save", async () => {
			const clientId = "https://failed-save.example/metadata.json";
			const barrier = deferred<Response>();
			const fetchClientMetadataResource = vi.fn(() => barrier.promise);
			const discovery = createCimdClientDiscovery({
				fetchClientMetadataResource,
			});
			const healthy = await createRequestContext();
			// This request's provider offers none of the document's grants.
			const broken = await createRequestContext({
				grantTypes: ["client_credentials"],
			});

			const resolvedBroken = Promise.resolve(
				discovery.resolve(broken.ctx, clientId, null),
			).then(
				() => "resolved",
				() => "rejected",
			);
			const resolvedHealthy = discovery.resolve(healthy.ctx, clientId, null);
			await vi.waitFor(() =>
				expect(fetchClientMetadataResource).toHaveBeenCalledTimes(1),
			);
			barrier.resolve(documentResponse(sampleMetadata(clientId)));

			expect(await resolvedBroken).toBe("rejected");
			expect((await resolvedHealthy)?.clientId).toBe(clientId);
		});

		it("fetches again after a fetched document could not be saved", async () => {
			const clientId = "https://unsaveable.example/metadata.json";
			let grantTypes = ["urn:example:unoffered-grant"];
			const fetchClientMetadataResource = vi.fn(async () =>
				documentResponse(sampleMetadata(clientId, { grant_types: grantTypes })),
			);
			const discovery = createCimdClientDiscovery({
				fetchClientMetadataResource,
				metadataFetchPolicy: { minimumFetchInterval: 0 },
			});
			const request = await createRequestContext();

			await expect(
				discovery.resolve(request.ctx, clientId, null),
			).rejects.toMatchObject({ body: { error: "invalid_client_metadata" } });
			grantTypes = ["authorization_code"];
			const client = await discovery.resolve(request.ctx, clientId, null);

			expect(client?.clientId).toBe(clientId);
			expect(fetchClientMetadataResource).toHaveBeenCalledTimes(2);
		});

		it("holds the per-client minimum interval after a fetched document could not be saved", async () => {
			const clientId = "https://paced-unsaveable.example/metadata.json";
			const fetchClientMetadataResource = vi.fn(async () =>
				documentResponse(
					sampleMetadata(clientId, {
						grant_types: ["urn:example:unoffered-grant"],
					}),
				),
			);
			const discovery = createCimdClientDiscovery({
				fetchClientMetadataResource,
			});
			const request = await createRequestContext();

			await expect(
				discovery.resolve(request.ctx, clientId, null),
			).rejects.toMatchObject({ body: { error: "invalid_client_metadata" } });
			await expect(
				discovery.resolve(request.ctx, clientId, null),
			).rejects.toMatchObject({ body: { error: "temporarily_unavailable" } });
			expect(fetchClientMetadataResource).toHaveBeenCalledTimes(1);
		});
	});

	/**
	 * A refresh must not keep a value the document no longer lists.
	 *
	 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document
	 */
	it("clears every stored field that the document stops listing", async () => {
		const clientId = "https://fields-removed.example/metadata.json";
		const stale = await createRequestContext();
		const current = await createRequestContext();
		const jwks = {
			keys: [
				{
					kty: "EC",
					crv: "P-256",
					x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
					y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
					kid: "gone",
					alg: "ES256",
					use: "sig",
				},
			],
		};
		const listed = sampleMetadata(clientId, {
			client_name: "Listed",
			client_uri: "https://fields-removed.example/about",
			logo_uri: "https://fields-removed.example/logo.png",
			tos_uri: "https://fields-removed.example/tos",
			policy_uri: "https://fields-removed.example/policy",
			software_id: "listed-app",
			software_version: "1.0.0",
			contacts: ["owner@fields-removed.example"],
			token_endpoint_auth_method: "private_key_jwt",
			jwks,
			post_logout_redirect_uris: ["https://fields-removed.example/signed-out"],
			frontchannel_logout_uri: "https://client.example/logout",
			frontchannel_logout_session_required: true,
		});
		await createCimdClientDiscovery({
			fetchClientMetadataResource: async () => documentResponse(listed),
		}).resolve(stale.ctx, clientId, null);
		const staleClient = await stale.readClient(clientId);
		expect(staleClient).toMatchObject({
			name: "Listed",
			uri: "https://fields-removed.example/about",
			softwareId: "listed-app",
			postLogoutRedirectUris: ["https://fields-removed.example/signed-out"],
		});

		const bare = {
			client_id: clientId,
			redirect_uris: ["https://client.example/callback"],
		};
		const resolver = createCimdMetadataResolver({
			fetchClientMetadataResource: async () => documentResponse(bare),
		});
		const discovery = createCimdClientDiscovery({
			metadataResolver: resolver,
		});
		await discovery.resolve(current.ctx, clientId, null);
		await discovery.resolve(stale.ctx, clientId, staleClient);

		const refreshed = await stale.readClient(clientId);
		for (const field of [
			"name",
			"uri",
			"icon",
			"tos",
			"policy",
			"softwareId",
			"softwareVersion",
			"jwks",
			"frontchannelLogoutUri",
			"frontchannelLogoutSessionRequired",
		] as const) {
			expect(refreshed?.[field], field).toBeFalsy();
		}
		expect(refreshed?.contacts ?? []).toEqual([]);
		expect(refreshed?.postLogoutRedirectUris ?? []).toEqual([]);
		// A second cache hit finds the row current and saves nothing.
		const onClientRefreshed = vi.fn();
		const again = await createCimdClientDiscovery({
			metadataResolver: resolver,
			onClientRefreshed,
		}).resolve(stale.ctx, clientId, refreshed);
		expect(again).toBe(refreshed);
		expect(onClientRefreshed).not.toHaveBeenCalled();
	});

	/**
	 * @see https://openid.net/specs/openid-connect-frontchannel-1_0.html#RPLogout
	 */
	it("refreshes the stored client when the front-channel logout URI is removed", async () => {
		const clientId = "https://logout-removed.example/metadata.json";
		const stale = await createRequestContext();
		const current = await createRequestContext();
		const documentFor = (extra: Record<string, unknown>) =>
			sampleMetadata(clientId, extra);

		const beforeDiscovery = createCimdClientDiscovery({
			fetchClientMetadataResource: async () =>
				documentResponse(
					documentFor({
						frontchannel_logout_uri: "https://client.example/logout",
					}),
				),
		});
		await beforeDiscovery.resolve(stale.ctx, clientId, null);
		const staleClient = await stale.readClient(clientId);
		expect(staleClient?.frontchannelLogoutUri).toBeTruthy();

		const resolver = createCimdMetadataResolver({
			fetchClientMetadataResource: async () =>
				documentResponse(documentFor({})),
		});
		const discovery = createCimdClientDiscovery({
			metadataResolver: resolver,
		});
		await discovery.resolve(current.ctx, clientId, null);
		await discovery.resolve(stale.ctx, clientId, staleClient);

		expect(
			(await stale.readClient(clientId))?.frontchannelLogoutUri,
		).toBeFalsy();
	});

	/**
	 * @see https://github.com/better-auth/better-auth/issues/12358
	 */
	describe("requests that do not wait for each other's saves", () => {
		const neverSettles = () => new Promise<never>(() => {});

		function sharedDiscovery(
			fetchClientMetadataResource: NonNullable<
				CimdOptions["fetchClientMetadataResource"]
			>,
		) {
			return createCimdClientDiscovery({
				metadataResolver: createCimdMetadataResolver({
					fetchClientMetadataResource,
					metadataFetchPolicy: { minimumFetchInterval: 0 },
				}),
			});
		}

		it("does not hold a request for a joined request whose save never settles", async () => {
			const clientId = "https://stuck-joiner.example/metadata.json";
			const barrier = deferred<Response>();
			const fetchClientMetadataResource = vi.fn(async () =>
				documentResponse(sampleMetadata(clientId), "no-store"),
			);
			fetchClientMetadataResource.mockImplementationOnce(() => barrier.promise);
			const discovery = sharedDiscovery(fetchClientMetadataResource);
			const leader = await createRequestContext();
			const joiner = await createRequestContext();
			const later = await createRequestContext();
			vi.spyOn(
				joiner.ctx.context.adapter,
				"transaction",
			).mockImplementationOnce(neverSettles);

			const leaderResolution = discovery.resolve(leader.ctx, clientId, null);
			void discovery.resolve(joiner.ctx, clientId, null);
			await vi.waitFor(() =>
				expect(fetchClientMetadataResource).toHaveBeenCalledTimes(1),
			);
			barrier.resolve(documentResponse(sampleMetadata(clientId), "no-store"));

			expect((await leaderResolution)?.clientId).toBe(clientId);
			expect(
				(await discovery.resolve(later.ctx, clientId, null))?.clientId,
			).toBe(clientId);
			expect(fetchClientMetadataResource).toHaveBeenCalledTimes(2);
		});

		it("does not hold a request for the fetching request's save that never settles", async () => {
			const clientId = "https://stuck-leader.example/metadata.json";
			const barrier = deferred<Response>();
			const fetchClientMetadataResource = vi.fn(async () =>
				documentResponse(sampleMetadata(clientId), "no-store"),
			);
			fetchClientMetadataResource.mockImplementationOnce(() => barrier.promise);
			const discovery = sharedDiscovery(fetchClientMetadataResource);
			const leader = await createRequestContext();
			const joiner = await createRequestContext();
			const later = await createRequestContext();
			vi.spyOn(
				leader.ctx.context.adapter,
				"transaction",
			).mockImplementationOnce(neverSettles);

			void discovery.resolve(leader.ctx, clientId, null);
			const joinerResolution = discovery.resolve(joiner.ctx, clientId, null);
			await vi.waitFor(() =>
				expect(fetchClientMetadataResource).toHaveBeenCalledTimes(1),
			);
			barrier.resolve(documentResponse(sampleMetadata(clientId), "no-store"));

			expect((await joinerResolution)?.clientId).toBe(clientId);
			expect(
				(await discovery.resolve(later.ctx, clientId, null))?.clientId,
			).toBe(clientId);
			expect(fetchClientMetadataResource).toHaveBeenCalledTimes(2);
		});

		it("leaves a joined request's pending save and later requests alone when the fetching request's save fails", async () => {
			const clientId = "https://failed-leader.example/metadata.json";
			const barrier = deferred<Response>();
			const fetchClientMetadataResource = vi.fn(async () =>
				documentResponse(sampleMetadata(clientId), "no-store"),
			);
			fetchClientMetadataResource.mockImplementationOnce(() => barrier.promise);
			const discovery = sharedDiscovery(fetchClientMetadataResource);
			const leader = await createRequestContext();
			const joiner = await createRequestContext();
			const later = await createRequestContext();
			vi.spyOn(leader.ctx.context.adapter, "transaction").mockRejectedValueOnce(
				new Error("forced client persistence failure"),
			);
			const saveGate = deferred<void>();
			const transaction = joiner.ctx.context.adapter.transaction.bind(
				joiner.ctx.context.adapter,
			);
			vi.spyOn(
				joiner.ctx.context.adapter,
				"transaction",
			).mockImplementationOnce(async (run) => {
				await saveGate.promise;
				return transaction(run);
			});

			const leaderResolution = discovery.resolve(leader.ctx, clientId, null);
			const joinerResolution = discovery.resolve(joiner.ctx, clientId, null);
			await vi.waitFor(() =>
				expect(fetchClientMetadataResource).toHaveBeenCalledTimes(1),
			);
			barrier.resolve(documentResponse(sampleMetadata(clientId), "no-store"));
			await expect(leaderResolution).rejects.toThrow(
				"forced client persistence failure",
			);

			expect(
				(await discovery.resolve(later.ctx, clientId, null))?.clientId,
			).toBe(clientId);
			expect(fetchClientMetadataResource).toHaveBeenCalledTimes(2);
			saveGate.resolve();
			expect((await joinerResolution)?.clientId).toBe(clientId);
			expect((await joiner.readClient(clientId))?.clientId).toBe(clientId);
		});

		/**
		 * Two refreshes of one client can overlap when a document is not cacheable.
		 * The resolver does not order their saves, and the next fetch stores the
		 * document the origin serves then.
		 */
		it("converges on the served document when two refreshes save out of order", async () => {
			const clientId = "https://overlapping-refresh.example/metadata.json";
			const names = ["Seed", "First", "Second", "Second"];
			const fetchClientMetadataResource = vi.fn(async () =>
				documentResponse(
					sampleMetadata(clientId, { client_name: names.shift() }),
					"no-store",
				),
			);
			const discovery = createCimdClientDiscovery({
				fetchClientMetadataResource,
				metadataFetchPolicy: { minimumFetchInterval: 0 },
			});
			const { ctx, readClient } = await createRequestContext();
			const seeded = await discovery.resolve(ctx, clientId, null);
			const { adapter } = ctx.context;
			const transaction = adapter.transaction.bind(adapter);
			const saveGate = deferred<void>();
			vi.spyOn(adapter, "transaction").mockImplementationOnce(async (run) => {
				await saveGate.promise;
				return transaction(run);
			});

			const first = discovery.resolve(ctx, clientId, seeded);
			await vi.waitFor(() =>
				expect(fetchClientMetadataResource).toHaveBeenCalledTimes(2),
			);
			await new Promise((resolve) => setTimeout(resolve, 10));
			const second = await discovery.resolve(ctx, clientId, seeded);
			saveGate.resolve();
			const firstClient = await first;

			expect(firstClient?.name).toBe("First");
			expect(second?.name).toBe("Second");
			const converged = await discovery.resolve(
				ctx,
				clientId,
				await readClient(clientId),
			);
			expect(converged?.name).toBe("Second");
			expect((await readClient(clientId))?.name).toBe("Second");
		});
	});

	/**
	 * A runtime that ends the request that started a fetch can leave the fetch
	 * pending forever.
	 *
	 * @see https://github.com/better-auth/better-auth/issues/12358
	 */
	describe("a fetch that never settles", () => {
		afterEach(() => {
			vi.useRealTimers();
		});

		it("lets a joined request fetch for itself and returns the abandoned fetch's permit", async () => {
			const clientId = "https://abandoned-fetch.example/metadata.json";
			const fetchClientMetadataResource = vi.fn(async () =>
				documentResponse(sampleMetadata(clientId)),
			);
			fetchClientMetadataResource.mockImplementationOnce(
				() => new Promise<Response>(() => {}),
			);
			const resolve = createCimdMetadataResolver({
				fetchClientMetadataResource,
				metadataFetchPolicy: {
					minimumFetchInterval: 0,
					maximumConcurrentFetches: 1,
				},
			});
			const { ctx } = await createRequestContext();
			vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });

			void resolve(ctx, clientId);
			await vi.advanceTimersByTimeAsync(0);
			expect(fetchClientMetadataResource).toHaveBeenCalledTimes(1);
			const joined = resolve(ctx, clientId);
			await vi.advanceTimersByTimeAsync(9_999);
			expect(fetchClientMetadataResource).toHaveBeenCalledTimes(1);
			await vi.advanceTimersByTimeAsync(1);

			expect(await joined).toMatchObject({
				fromCache: false,
				metadata: { client_id: clientId },
			});
			expect(fetchClientMetadataResource).toHaveBeenCalledTimes(2);
			expect(await resolve(ctx, clientId)).toMatchObject({ fromCache: true });
			expect(fetchClientMetadataResource).toHaveBeenCalledTimes(2);
		});

		it("keeps an abandoned fetch that finishes later from overwriting the fetch that replaced it", async () => {
			const clientId = "https://abandoned-late.example/metadata.json";
			const lateResponse = deferred<Response>();
			const fetchClientMetadataResource = vi.fn(async () =>
				documentResponse(
					sampleMetadata(clientId, { client_name: "Replacement" }),
				),
			);
			fetchClientMetadataResource.mockImplementationOnce(
				() => lateResponse.promise,
			);
			const resolve = createCimdMetadataResolver({
				fetchClientMetadataResource,
				metadataFetchPolicy: { minimumFetchInterval: 0 },
			});
			const { ctx } = await createRequestContext();
			vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });

			const leader = resolve(ctx, clientId);
			await vi.advanceTimersByTimeAsync(0);
			const joined = resolve(ctx, clientId);
			await vi.advanceTimersByTimeAsync(10_000);
			expect(await joined).toMatchObject({
				metadata: { client_name: "Replacement" },
			});

			// A transport that ignores the abort signal can still answer late. Its
			// body is read without the signal, so the document is valid.
			const late = documentResponse(
				sampleMetadata(clientId, { client_name: "Abandoned" }),
			);
			Object.defineProperty(late, "body", { value: null });
			lateResponse.resolve(late);
			expect(await leader).toMatchObject({
				fromCache: false,
				metadata: { client_name: "Replacement" },
			});

			expect(await resolve(ctx, clientId)).toMatchObject({
				fromCache: true,
				metadata: { client_name: "Replacement" },
			});
			expect(fetchClientMetadataResource).toHaveBeenCalledTimes(2);
		});

		it("does not let an abandoned fetch that fails later pace the fetch that replaced it", async () => {
			const clientId = "https://abandoned-failure.example/metadata.json";
			let failLeader!: (error: Error) => void;
			const fetchClientMetadataResource = vi.fn(async () =>
				documentResponse(sampleMetadata(clientId), "no-store"),
			);
			fetchClientMetadataResource.mockImplementationOnce(
				() =>
					new Promise<Response>((_resolve, reject) => {
						failLeader = reject;
					}),
			);
			const resolve = createCimdMetadataResolver({
				fetchClientMetadataResource,
				metadataFetchPolicy: { minimumFetchInterval: 3_600 },
			});
			const { ctx } = await createRequestContext();
			vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });

			const leader = resolve(ctx, clientId);
			const leaderOutcome = leader.then(
				() => "resolved",
				() => "rejected",
			);
			await vi.advanceTimersByTimeAsync(0);
			const joined = resolve(ctx, clientId);
			await vi.advanceTimersByTimeAsync(10_000);
			// The abandoned fetch's pacing record is gone, so the replacement ran.
			expect(await joined).toMatchObject({ fromCache: false });

			failLeader(new Error("transport failed"));
			expect(await leaderOutcome).toBe("rejected");
			expect(await resolve(ctx, clientId)).toMatchObject({ fromCache: false });
			expect(fetchClientMetadataResource).toHaveBeenCalledTimes(3);
		});

		it("gives a fetch that never settles its concurrency slot back after the lease", async () => {
			const stuckClientId = "https://lease-stuck.example/metadata.json";
			const otherClientId = "https://lease-other.example/metadata.json";
			const fetchClientMetadataResource = vi.fn(
				async (input: RequestInfo | URL) =>
					documentResponse(sampleMetadata(String(input))),
			);
			fetchClientMetadataResource.mockImplementationOnce(
				() => new Promise<Response>(() => {}),
			);
			const resolve = createCimdMetadataResolver({
				fetchClientMetadataResource,
				metadataFetchPolicy: {
					minimumFetchInterval: 0,
					maximumConcurrentFetches: 1,
				},
			});
			const { ctx } = await createRequestContext();
			vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });

			void resolve(ctx, stuckClientId);
			await vi.advanceTimersByTimeAsync(9_999);
			await expect(resolve(ctx, otherClientId)).rejects.toMatchObject({
				body: { error: "temporarily_unavailable" },
			});
			await vi.advanceTimersByTimeAsync(1);

			expect(await resolve(ctx, otherClientId)).toMatchObject({
				fromCache: false,
				metadata: { client_id: otherClientId },
			});
			expect(fetchClientMetadataResource).toHaveBeenCalledTimes(2);
		});

		it("does not save a retired fetch's document over the document that replaced it", async () => {
			const clientId = "https://retired-save.example/metadata.json";
			const lateResponse = deferred<Response>();
			const fetchClientMetadataResource = vi.fn(async () =>
				documentResponse(
					sampleMetadata(clientId, { client_name: "Replacement" }),
				),
			);
			fetchClientMetadataResource.mockImplementationOnce(
				() => lateResponse.promise,
			);
			const discovery = createCimdClientDiscovery({
				fetchClientMetadataResource,
				metadataFetchPolicy: { minimumFetchInterval: 0 },
			});
			const { ctx, readClient } = await createRequestContext();
			vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });

			const leader = discovery.resolve(ctx, clientId, null);
			await vi.advanceTimersByTimeAsync(0);
			const joined = discovery.resolve(ctx, clientId, null);
			await vi.advanceTimersByTimeAsync(10_000);
			expect((await joined)?.name).toBe("Replacement");

			// The retired fetch answers late with the older document. Its body is
			// read without the abort signal, so the document is valid.
			const late = documentResponse(
				sampleMetadata(clientId, { client_name: "Retired" }),
			);
			Object.defineProperty(late, "body", { value: null });
			lateResponse.resolve(late);
			expect((await leader)?.name).toBe("Replacement");

			// The cached document is fresh, so the next request trusts the row.
			const stored = await readClient(clientId);
			expect(stored?.name).toBe("Replacement");
			expect(await discovery.resolve(ctx, clientId, stored)).toBe(stored);
			expect(fetchClientMetadataResource).toHaveBeenCalledTimes(2);
		});

		it("saves the client for a joined request that fetched for itself", async () => {
			const clientId = "https://abandoned-then-saved.example/metadata.json";
			const fetchClientMetadataResource = vi.fn(async () =>
				documentResponse(sampleMetadata(clientId)),
			);
			fetchClientMetadataResource.mockImplementationOnce(
				() => new Promise<Response>(() => {}),
			);
			const discovery = createCimdClientDiscovery({
				metadataResolver: createCimdMetadataResolver({
					fetchClientMetadataResource,
					metadataFetchPolicy: { minimumFetchInterval: 0 },
				}),
			});
			const leader = await createRequestContext();
			const joiner = await createRequestContext();
			const later = await createRequestContext();
			vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });

			void discovery.resolve(leader.ctx, clientId, null);
			await vi.advanceTimersByTimeAsync(0);
			const joined = discovery.resolve(joiner.ctx, clientId, null);
			await vi.advanceTimersByTimeAsync(10_000);

			expect((await joined)?.clientId).toBe(clientId);
			expect((await joiner.readClient(clientId))?.clientId).toBe(clientId);
			expect(
				(await discovery.resolve(later.ctx, clientId, null))?.clientId,
			).toBe(clientId);
			expect(fetchClientMetadataResource).toHaveBeenCalledTimes(2);
		});
	});

	describe("createCimdMetadataResolver", () => {
		it("resolves a document and then answers from the cache", async () => {
			const clientId = "https://standalone.example/metadata.json";
			const fetchClientMetadataResource = vi.fn(async () =>
				documentResponse(sampleMetadata(clientId)),
			);
			const resolve = createCimdMetadataResolver({
				fetchClientMetadataResource,
			});
			const { ctx } = await createRequestContext();

			const fetched = await resolve(ctx, clientId);
			const cached = await resolve(ctx, clientId);

			expect(fetched).toMatchObject({
				metadata: { client_id: clientId, client_name: "Test Client" },
				fromCache: false,
			});
			expect(cached).toMatchObject({
				metadata: fetched?.metadata,
				fromCache: true,
			});
			expect(fetchClientMetadataResource).toHaveBeenCalledTimes(1);
		});

		it("returns null for a client_id that is not a metadata document URL", async () => {
			const fetchClientMetadataResource = vi.fn();
			const resolve = createCimdMetadataResolver({
				fetchClientMetadataResource,
			});
			const { ctx } = await createRequestContext();

			expect(await resolve(ctx, "plain-client")).toBeNull();
			expect(await resolve(ctx, "http://insecure.example/client")).toBeNull();
			expect(fetchClientMetadataResource).not.toHaveBeenCalled();
		});

		it("hands each caller its own copy of the document", async () => {
			const clientId = "https://copies.example/metadata.json";
			const barrier = deferred<Response>();
			const resolve = createCimdMetadataResolver({
				fetchClientMetadataResource: () => barrier.promise,
			});
			const { ctx } = await createRequestContext();

			const first = resolve(ctx, clientId);
			const joined = resolve(ctx, clientId);
			barrier.resolve(documentResponse(sampleMetadata(clientId)));
			const [firstResolution, joinedResolution] = await Promise.all([
				first,
				joined,
			]);
			if (!firstResolution || !joinedResolution) throw new Error("no result");
			firstResolution.metadata.client_name = "Changed";
			firstResolution.metadata.redirect_uris = ["https://evil.example/cb"];

			expect(joinedResolution.metadata.client_name).toBe("Test Client");
			const cached = await resolve(ctx, clientId);
			expect(cached?.metadata.client_name).toBe("Test Client");
			expect(cached?.metadata.redirect_uris).toEqual([
				"https://client.example/callback",
			]);
		});

		it("runs the URL policy with each request's context before any fetch", async () => {
			const clientId = "https://policy.example/metadata.json";
			const fetchClientMetadataResource = vi.fn(async () =>
				documentResponse(sampleMetadata(clientId)),
			);
			const isMetadataDocumentUrlAllowed = vi.fn<
				NonNullable<CimdOptions["isMetadataDocumentUrlAllowed"]>
			>(async () => true);
			const resolve = createCimdMetadataResolver({
				fetchClientMetadataResource,
				isMetadataDocumentUrlAllowed,
			});
			const requestA = await createRequestContext();
			const requestB = await createRequestContext();

			await Promise.all([
				resolve(requestA.ctx, clientId),
				resolve(requestB.ctx, clientId),
			]);

			expect(fetchClientMetadataResource).toHaveBeenCalledTimes(1);
			expect(isMetadataDocumentUrlAllowed).toHaveBeenCalledWith(
				clientId,
				requestA.ctx,
			);
			expect(isMetadataDocumentUrlAllowed).toHaveBeenCalledWith(
				clientId,
				requestB.ctx,
			);
		});

		it("does not run the URL policy for a fresh cache hit", async () => {
			const clientId = "https://policy-hit.example/metadata.json";
			const isMetadataDocumentUrlAllowed = vi.fn<
				NonNullable<CimdOptions["isMetadataDocumentUrlAllowed"]>
			>(async () => true);
			const resolve = createCimdMetadataResolver({
				fetchClientMetadataResource: async () =>
					documentResponse(sampleMetadata(clientId)),
				isMetadataDocumentUrlAllowed,
			});
			const { ctx } = await createRequestContext();

			await resolve(ctx, clientId);
			await resolve(ctx, clientId);

			expect(isMetadataDocumentUrlAllowed).toHaveBeenCalledTimes(1);
		});
	});

	describe("discovery with a shared resolver", () => {
		const transport =
			vi.fn<NonNullable<CimdOptions["fetchClientMetadataResource"]>>();

		function discoveryFor(
			metadataResolver: CimdMetadataResolver,
			options: Pick<CimdOptions, "onClientCreated" | "onClientRefreshed"> = {},
		) {
			return createCimdClientDiscovery({ metadataResolver, ...options });
		}

		it("shares one fetch between per-request discoveries and saves in each request's database", async () => {
			const clientId = "https://shared.example/metadata.json";
			const barrier = deferred<Response>();
			const fetchClientMetadataResource = vi.fn(() => barrier.promise);
			const resolver = createCimdMetadataResolver({
				fetchClientMetadataResource,
			});
			const requestA = await createRequestContext();
			const requestB = await createRequestContext();

			const resolvedA = discoveryFor(resolver).resolve(
				requestA.ctx,
				clientId,
				null,
			);
			const resolvedB = discoveryFor(resolver).resolve(
				requestB.ctx,
				clientId,
				null,
			);
			await vi.waitFor(() =>
				expect(fetchClientMetadataResource).toHaveBeenCalledTimes(1),
			);
			barrier.resolve(documentResponse(sampleMetadata(clientId)));
			await Promise.all([resolvedA, resolvedB]);

			expect(fetchClientMetadataResource).toHaveBeenCalledTimes(1);
			expect((await requestA.readClient(clientId))?.clientId).toBe(clientId);
			expect((await requestB.readClient(clientId))?.clientId).toBe(clientId);
		});

		it("keeps the cached document when one request cannot save it", async () => {
			const clientId = "https://shared-failed-save.example/metadata.json";
			const fetchClientMetadataResource = vi.fn(async () =>
				documentResponse(sampleMetadata(clientId)),
			);
			const discovery = discoveryFor(
				createCimdMetadataResolver({ fetchClientMetadataResource }),
			);
			const broken = await createRequestContext({
				grantTypes: ["client_credentials"],
			});
			const healthy = await createRequestContext();

			await expect(
				discovery.resolve(broken.ctx, clientId, null),
			).rejects.toMatchObject({ body: { error: "invalid_client_metadata" } });
			const client = await discovery.resolve(healthy.ctx, clientId, null);

			expect(client?.clientId).toBe(clientId);
			expect(fetchClientMetadataResource).toHaveBeenCalledTimes(1);
		});

		it("applies the policy set on the resolver to a discovery that uses it", async () => {
			const clientId = "https://refused.example/metadata.json";
			const fetchClientMetadataResource = vi.fn();
			const resolver = createCimdMetadataResolver({
				fetchClientMetadataResource,
				isMetadataDocumentUrlAllowed: () => false,
			});
			const request = await createRequestContext();

			await expect(
				discoveryFor(resolver).resolve(request.ctx, clientId, null),
			).rejects.toMatchObject({
				status: "BAD_REQUEST",
				body: {
					error: "invalid_client",
					error_description:
						"client_id URL is not permitted by the server's fetch policy",
				},
			});
			expect(fetchClientMetadataResource).not.toHaveBeenCalled();
		});

		it("applies the metadata profile set on the resolver", async () => {
			const clientId = "https://profile.example/metadata.json";
			const resolver = createCimdMetadataResolver({
				fetchClientMetadataResource: async () =>
					documentResponse(
						sampleMetadata(clientId, { client_name: undefined }),
					),
				metadataProfile: "mcp-2026-07-28",
			});
			const request = await createRequestContext();

			await expect(
				discoveryFor(resolver).resolve(request.ctx, clientId, null),
			).rejects.toMatchObject({
				body: {
					error: "invalid_client",
					error_description: "client_name must be a non-empty string",
				},
			});
		});

		it("applies the origin-bound fields set on the resolver", async () => {
			const clientId = "https://bound.example/metadata.json";
			const document = sampleMetadata(clientId, {
				client_uri: "https://elsewhere.example/about",
			});
			const request = await createRequestContext();

			const bound = createCimdMetadataResolver({
				fetchClientMetadataResource: async () => documentResponse(document),
			});
			await expect(
				discoveryFor(bound).resolve(request.ctx, clientId, null),
			).rejects.toMatchObject({ body: { error: "invalid_client" } });

			const unbound = createCimdMetadataResolver({
				fetchClientMetadataResource: async () => documentResponse(document),
				originBoundFields: [],
			});
			const client = await discoveryFor(unbound).resolve(
				request.ctx,
				clientId,
				null,
			);
			expect(client?.uri).toBe("https://elsewhere.example/about");
		});

		it.each([
			["fetchClientMetadataResource", transport],
			["isMetadataDocumentUrlAllowed", () => true],
			["maxCacheEntries", 10],
			["metadataFetchPolicy", { minimumFetchInterval: 0 }],
			["metadataProfile", "mcp-2026-07-28"],
			["metadataRevalidationInterval", "10m"],
			["originBoundFields", []],
		] as const)("rejects %s next to a shared resolver", (option, value) => {
			const resolver = createCimdMetadataResolver({
				fetchClientMetadataResource: transport,
			});
			// TypeScript rejects this combination; JavaScript callers reach the check.
			const options = {
				metadataResolver: resolver,
				[option]: value,
			} as unknown as CimdOptions;

			expect(() => createCimdClientDiscovery(options)).toThrow(BetterAuthError);
			expect(() => createCimdClientDiscovery(options)).toThrow(option);
		});

		it("fetches discovery-owned resources with the shared resolver's transport", () => {
			const resolver = createCimdMetadataResolver({
				fetchClientMetadataResource: transport,
			});

			const discovery = discoveryFor(resolver);

			expect(discovery.fetchClientMetadataResource).toBe(transport);
		});

		it("rejects a shared resolver that carries no transport", () => {
			const resolver = (async () => null) as unknown as CimdMetadataResolver;

			expect(() =>
				createCimdClientDiscovery({ metadataResolver: resolver }),
			).toThrow("fetchClientMetadataResource");
		});

		/**
		 * A resolver shared with other discoveries can hold a document that was saved
		 * through another database, so a cache hit has to check this database's row.
		 */
		describe("reconciling a stored client with a cached document", () => {
			async function jwksFor(keyId: string) {
				const { publicKey } = (await crypto.subtle.generateKey(
					{ name: "ECDSA", namedCurve: "P-256" },
					true,
					["sign", "verify"],
				)) as CryptoKeyPair;
				const jwk = await crypto.subtle.exportKey("jwk", publicKey);
				return { keys: [{ ...jwk, kid: keyId, alg: "ES256", use: "sig" }] };
			}

			const fieldChanges: Array<
				[field: string, before: unknown, after: unknown, extra?: object]
			> = [
				["client_name", "Old Name", "New Name"],
				[
					"client_uri",
					"https://reconcile.example/a",
					"https://reconcile.example/b",
				],
				[
					"logo_uri",
					"https://reconcile.example/a.png",
					"https://reconcile.example/b.png",
				],
				[
					"tos_uri",
					"https://reconcile.example/a-tos",
					"https://reconcile.example/b-tos",
				],
				[
					"policy_uri",
					"https://reconcile.example/a-p",
					"https://reconcile.example/b-p",
				],
				["software_id", "app-a", "app-b"],
				["software_version", "1.0.0", "2.0.0"],
				["contacts", ["a@reconcile.example"], ["b@reconcile.example"]],
				[
					"redirect_uris",
					["https://client.example/callback"],
					["https://client.example/callback", "https://client.example/other"],
				],
				["application_type", "web", "native"],
				["dpop_bound_access_tokens", false, true],
				["dpop_bound_access_tokens", true, false],
				["require_pushed_authorization_requests", false, true],
				["subject_type", "public", "pairwise"],
				[
					"frontchannel_logout_uri",
					"https://client.example/logout-a",
					"https://client.example/logout-b",
				],
				["frontchannel_logout_session_required", false, true],
			];

			it.each(fieldChanges)(
				"refreshes the stored client when %s changed (%j to %j)",
				async (field, before, after) => {
					const clientId = `https://reconcile.example/${field}-${JSON.stringify(after).length}.json`;
					const stale = await createRequestContext(RICH_PROVIDER_OPTIONS);
					const current = await createRequestContext(RICH_PROVIDER_OPTIONS);
					const documentFor = (value: unknown) =>
						sampleMetadata(clientId, { [field]: value });

					// The stale database saved the document as it was before.
					const beforeDiscovery = discoveryFor(
						createCimdMetadataResolver({
							fetchClientMetadataResource: async () =>
								documentResponse(documentFor(before)),
						}),
					);
					await beforeDiscovery.resolve(stale.ctx, clientId, null);
					const staleClient = await stale.readClient(clientId);

					// Another request through the shared resolver caches the new document.
					const resolver = createCimdMetadataResolver({
						fetchClientMetadataResource: async () =>
							documentResponse(documentFor(after)),
					});
					const discovery = discoveryFor(resolver);
					await discovery.resolve(current.ctx, clientId, null);

					const refreshed = await discovery.resolve(
						stale.ctx,
						clientId,
						staleClient,
					);
					expect(await stale.readClient(clientId)).toEqual(refreshed);
					expect(refreshed).not.toEqual(staleClient);
				},
			);

			it("refreshes the stored client when the key set changed", async () => {
				const clientId = "https://reconcile.example/jwks.json";
				const stale = await createRequestContext();
				const current = await createRequestContext();
				const documentFor = (jwks: unknown) =>
					sampleMetadata(clientId, {
						token_endpoint_auth_method: "private_key_jwt",
						jwks,
					});
				const beforeJwks = await jwksFor("before");
				const afterJwks = await jwksFor("after");
				await discoveryFor(
					createCimdMetadataResolver({
						fetchClientMetadataResource: async () =>
							documentResponse(documentFor(beforeJwks)),
					}),
				).resolve(stale.ctx, clientId, null);
				const staleClient = await stale.readClient(clientId);

				const discovery = discoveryFor(
					createCimdMetadataResolver({
						fetchClientMetadataResource: async () =>
							documentResponse(documentFor(afterJwks)),
					}),
				);
				await discovery.resolve(current.ctx, clientId, null);
				await discovery.resolve(stale.ctx, clientId, staleClient);

				expect(
					JSON.parse((await stale.readClient(clientId))?.jwks ?? ""),
				).toEqual(afterJwks);
			});

			it("does not save again when the stored client already matches", async () => {
				const clientId = "https://reconcile.example/matching.json";
				const jwks = await jwksFor("matching");
				const document = sampleMetadata(clientId, {
					client_uri: "https://reconcile.example/about",
					logo_uri: "https://reconcile.example/logo.png",
					tos_uri: "https://reconcile.example/tos",
					policy_uri: "https://reconcile.example/policy",
					contacts: ["owner@reconcile.example"],
					software_id: "matching-app",
					software_version: "3.1.4",
					application_type: "web",
					dpop_bound_access_tokens: true,
					require_pushed_authorization_requests: true,
					token_endpoint_auth_method: "private_key_jwt",
					jwks,
					redirect_uris: [
						"https://client.example/callback",
						"https://client.example/second",
					],
				});
				const onClientRefreshed = vi.fn();
				const discovery = discoveryFor(
					createCimdMetadataResolver({
						fetchClientMetadataResource: async () => documentResponse(document),
					}),
					{ onClientRefreshed },
				);
				const request = await createRequestContext(RICH_PROVIDER_OPTIONS);

				await discovery.resolve(request.ctx, clientId, null);
				const stored = await request.readClient(clientId);
				const again = await discovery.resolve(request.ctx, clientId, stored);

				expect(again).toBe(stored);
				expect(onClientRefreshed).not.toHaveBeenCalled();
			});

			it("does not save again when the provider has no scopes", async () => {
				const clientId = "https://reconcile.example/no-scopes.json";
				const onClientRefreshed = vi.fn();
				const discovery = discoveryFor(
					createCimdMetadataResolver({
						fetchClientMetadataResource: async () =>
							documentResponse(sampleMetadata(clientId)),
					}),
					{ onClientRefreshed },
				);
				const request = await createRequestContext({ scopes: [] });

				await discovery.resolve(request.ctx, clientId, null);
				const stored = await request.readClient(clientId);
				const again = await discovery.resolve(request.ctx, clientId, stored);

				expect(again).toBe(stored);
				expect(onClientRefreshed).not.toHaveBeenCalled();
			});

			it("does not save again a client for a minimal document", async () => {
				const clientId = "https://reconcile.example/minimal.json";
				const onClientRefreshed = vi.fn();
				const discovery = discoveryFor(
					createCimdMetadataResolver({
						fetchClientMetadataResource: async () =>
							documentResponse({
								client_id: clientId,
								redirect_uris: ["https://client.example/callback"],
							}),
					}),
					{ onClientRefreshed },
				);
				const request = await createRequestContext();

				await discovery.resolve(request.ctx, clientId, null);
				const stored = await request.readClient(clientId);
				const again = await discovery.resolve(request.ctx, clientId, stored);

				expect(again).toBe(stored);
				expect(onClientRefreshed).not.toHaveBeenCalled();
			});

			describe("grant types and scopes", () => {
				/**
				 * A document that leaves the grants out registers the client with the
				 * default grant, so a stored client that kept a wider list from an
				 * older document is stale.
				 */
				it("refreshes the stored client when the document stops listing grant_types", async () => {
					const clientId = "https://reconcile.example/dropped-grants.json";
					const onClientRefreshed = vi.fn();
					const staleRequest = await createRequestContext();
					const currentRequest = await createRequestContext();

					await discoveryFor(
						createCimdMetadataResolver({
							fetchClientMetadataResource: async () =>
								documentResponse(
									sampleMetadata(clientId, {
										grant_types: ["authorization_code", "refresh_token"],
									}),
								),
						}),
					).resolve(staleRequest.ctx, clientId, null);
					const staleClient = await staleRequest.readClient(clientId);
					expect(staleClient?.grantTypes).toEqual([
						"authorization_code",
						"refresh_token",
					]);

					const discovery = discoveryFor(
						createCimdMetadataResolver({
							fetchClientMetadataResource: async () =>
								documentResponse(
									sampleMetadata(clientId, { grant_types: undefined }),
								),
						}),
						{ onClientRefreshed },
					);
					await discovery.resolve(currentRequest.ctx, clientId, null);
					await discovery.resolve(staleRequest.ctx, clientId, staleClient);

					expect((await staleRequest.readClient(clientId))?.grantTypes).toEqual(
						["authorization_code"],
					);
					expect(onClientRefreshed).toHaveBeenCalledTimes(1);
				});

				it("refreshes the stored client when the document lists more grant_types", async () => {
					const clientId = "https://reconcile.example/added-grants.json";
					const staleRequest = await createRequestContext();
					const currentRequest = await createRequestContext();

					await discoveryFor(
						createCimdMetadataResolver({
							fetchClientMetadataResource: async () =>
								documentResponse(sampleMetadata(clientId)),
						}),
					).resolve(staleRequest.ctx, clientId, null);
					const staleClient = await staleRequest.readClient(clientId);

					const discovery = discoveryFor(
						createCimdMetadataResolver({
							fetchClientMetadataResource: async () =>
								documentResponse(
									sampleMetadata(clientId, {
										grant_types: ["authorization_code", "refresh_token"],
									}),
								),
						}),
					);
					await discovery.resolve(currentRequest.ctx, clientId, null);
					await discovery.resolve(staleRequest.ctx, clientId, staleClient);

					expect((await staleRequest.readClient(clientId))?.grantTypes).toEqual(
						["authorization_code", "refresh_token"],
					);
				});

				it("does not save again when the document lists fewer scopes than the server registers", async () => {
					const clientId = "https://reconcile.example/narrow-scope.json";
					const onClientRefreshed = vi.fn();
					const discovery = discoveryFor(
						createCimdMetadataResolver({
							fetchClientMetadataResource: async () =>
								documentResponse(sampleMetadata(clientId, { scope: "openid" })),
						}),
						{ onClientRefreshed },
					);
					const request = await createRequestContext({
						scopes: ["openid", "profile"],
					});

					await discovery.resolve(request.ctx, clientId, null);
					const stored = await request.readClient(clientId);
					const again = await discovery.resolve(request.ctx, clientId, stored);

					expect(again).toBe(stored);
					expect(onClientRefreshed).not.toHaveBeenCalled();
				});
			});
		});
	});

	describe("discovery without a shared resolver", () => {
		it("answers a cache hit with the stored client while a refresh is still saving", async () => {
			const clientId = "https://pending-save.example/metadata.json";
			const responses = [
				documentResponse(
					sampleMetadata(clientId, { client_name: "Seed" }),
					"max-age=0",
				),
				documentResponse(sampleMetadata(clientId, { client_name: "Newer" })),
			];
			const fetchClientMetadataResource = vi.fn(async () => {
				const response = responses.shift();
				if (!response) throw new Error("unexpected fetch");
				return response;
			});
			const discovery = createCimdClientDiscovery({
				fetchClientMetadataResource,
				metadataFetchPolicy: { minimumFetchInterval: 0 },
			});
			const { ctx, readClient } = await createRequestContext();
			const seeded = await discovery.resolve(ctx, clientId, null);

			const { adapter } = ctx.context;
			const transaction = adapter.transaction.bind(adapter);
			const saveGate = deferred<void>();
			vi.spyOn(adapter, "transaction").mockImplementationOnce(async (run) => {
				await saveGate.promise;
				return transaction(run);
			});

			const refreshing = discovery.resolve(ctx, clientId, seeded);
			await vi.waitFor(() =>
				expect(fetchClientMetadataResource).toHaveBeenCalledTimes(2),
			);
			await new Promise((resolve) => setTimeout(resolve, 10));
			const hit = await discovery.resolve(ctx, clientId, seeded);
			saveGate.resolve();
			await refreshing;

			expect(hit).toBe(seeded);
			expect((await readClient(clientId))?.name).toBe("Newer");
		});

		it("keeps a newer cached document when an older fetched document cannot be saved", async () => {
			const clientId = "https://owned-newer.example/metadata.json";
			const responses = [
				documentResponse(
					sampleMetadata(clientId, { client_name: "First" }),
					"max-age=0",
				),
				documentResponse(sampleMetadata(clientId, { client_name: "Second" })),
			];
			const fetchClientMetadataResource = vi.fn(async () => {
				const response = responses.shift();
				if (!response) throw new Error("unexpected fetch");
				return response;
			});
			const discovery = createCimdClientDiscovery({
				fetchClientMetadataResource,
				metadataFetchPolicy: { minimumFetchInterval: 0 },
			});
			const { ctx, readClient } = await createRequestContext();
			const saveGate = deferred<void>();
			vi.spyOn(ctx.context.adapter, "transaction").mockImplementationOnce(
				async () => {
					await saveGate.promise;
					throw new Error("forced client persistence failure");
				},
			);

			const first = discovery.resolve(ctx, clientId, null);
			await vi.waitFor(() =>
				expect(fetchClientMetadataResource).toHaveBeenCalledTimes(1),
			);
			await new Promise((resolve) => setTimeout(resolve, 10));
			const second = await discovery.resolve(ctx, clientId, null);
			saveGate.resolve();
			await expect(first).rejects.toThrow("forced client persistence failure");

			expect(second?.name).toBe("Second");
			const stored = await readClient(clientId);
			expect(await discovery.resolve(ctx, clientId, stored)).toBe(stored);
			expect(fetchClientMetadataResource).toHaveBeenCalledTimes(2);
		});

		it("returns the stored client on a cache hit", async () => {
			const clientId = "https://owned.example/metadata.json";
			const fetchClientMetadataResource = vi.fn(async () =>
				documentResponse(sampleMetadata(clientId)),
			);
			const onClientRefreshed = vi.fn();
			const discovery = createCimdClientDiscovery({
				fetchClientMetadataResource,
				onClientRefreshed,
			});
			const request = await createRequestContext();

			await discovery.resolve(request.ctx, clientId, null);
			const stored = await request.readClient(clientId);
			const again = await discovery.resolve(request.ctx, clientId, stored);

			expect(again).toBe(stored);
			expect(fetchClientMetadataResource).toHaveBeenCalledTimes(1);
			expect(onClientRefreshed).not.toHaveBeenCalled();
		});
	});
});
