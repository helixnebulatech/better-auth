// @vitest-environment node

import type { SuccessContext } from "@better-fetch/fetch";
import { Window } from "happy-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getTestInstance } from "../test-utils/test-instance";

type SessionState = {
	isPending: boolean;
	isRefetching: boolean;
	signedIn: boolean;
};

beforeEach(() => {
	const window = new Window({ url: "http://localhost:3000" });
	vi.stubGlobal("window", window);
	vi.stubGlobal("document", window.document);
	vi.stubGlobal("navigator", window.navigator);
});

afterEach(() => {
	vi.unstubAllGlobals();
});

type Client = Awaited<ReturnType<typeof getTestInstance>>["client"];

function recordSession(client: Client) {
	const states: SessionState[] = [];
	const unsubscribe = client.useSession.subscribe((state) => {
		states.push({
			isPending: state.isPending,
			isRefetching: state.isRefetching,
			signedIn: state.data !== null,
		});
	});
	const settled = () =>
		vi.waitFor(() => {
			expect(states.at(-1)).toMatchObject({
				isPending: false,
				isRefetching: false,
			});
		});
	return {
		states,
		settled,
		unsubscribe,
	};
}

/**
 * @see https://github.com/better-auth/better-auth/issues/12074
 */
describe("session refetch while signed out", () => {
	it("keeps isPending false and reports the refetch through isRefetching", async () => {
		const { client } = await getTestInstance();
		const { states, settled, unsubscribe } = recordSession(client);
		await settled();
		expect(states.at(-1)?.signedIn).toBe(false);

		states.length = 0;
		await client.useSession.get().refetch();
		await settled();
		unsubscribe();

		expect(states).toContainEqual({
			isPending: false,
			isRefetching: true,
			signedIn: false,
		});
		expect(states).not.toContainEqual(
			expect.objectContaining({ isPending: true }),
		);
	});

	it("keeps isPending false when signing out while signed out", async () => {
		const { client } = await getTestInstance();
		const { states, settled, unsubscribe } = recordSession(client);
		await settled();

		states.length = 0;
		await client.signOut();
		await settled();
		unsubscribe();

		expect(states).not.toContainEqual(
			expect.objectContaining({ isPending: true }),
		);
	});
});

describe("session after sign-in", () => {
	const delay = () => new Promise((resolve) => setTimeout(resolve, 5));

	// Reuse the test user's request context with an empty cookie jar, so the
	// sign-in starts signed out and its session refetch sends the cookie.
	async function signedOutInstance() {
		let persist: (context: SuccessContext) => Promise<void> = async () => {};
		let beforeSessionResponse: () => Promise<void> = async () => {};
		let sessionRequests = 0;
		const instance = await getTestInstance(undefined, {
			clientOptions: {
				plugins: [
					{
						id: "persist-credentials",
						fetchPlugins: [
							{
								id: "persist-credentials",
								name: "persist-credentials",
								hooks: {
									async onResponse(context) {
										if (
											!context.request.url.toString().endsWith("/get-session")
										)
											return;
										sessionRequests++;
										await beforeSessionResponse();
									},
									onSuccess: (context) => persist(context),
								},
							},
						],
					},
				],
			},
		});
		const { headers, runWithUser } = await instance.signInWithTestUser();
		headers.delete("cookie");
		const setCookie = instance.sessionSetter(headers);
		return {
			...instance,
			runWithUser,
			setCookie,
			sessionRequests: () => sessionRequests,
			persistWith(next: typeof persist) {
				persist = next;
			},
			beforeSessionResponse(next: typeof beforeSessionResponse) {
				beforeSessionResponse = next;
			},
		};
	}

	const signedIn = {
		isPending: false,
		isRefetching: false,
		signedIn: true,
	};

	function expectNoSettledSignedOut(states: SessionState[]) {
		// A settled signed-out state would bounce guarded pages back to sign-in.
		expect(states).not.toContainEqual({
			isPending: false,
			isRefetching: false,
			signedIn: false,
		});
	}

	function current(client: Client): SessionState {
		const state = client.useSession.get();
		return {
			isPending: state.isPending,
			isRefetching: state.isRefetching,
			signedIn: state.data !== null,
		};
	}

	it("resolves once the session has loaded with the credentials the per-call onSuccess persisted", async () => {
		const { client, testUser, runWithUser, setCookie } =
			await signedOutInstance();
		await runWithUser(async () => {
			const { states, settled, unsubscribe } = recordSession(client);
			await settled();
			states.length = 0;

			let inOnSuccess: boolean | undefined;
			await client.signIn.email({
				email: testUser.email,
				password: testUser.password,
				fetchOptions: {
					async onSuccess(context) {
						inOnSuccess = client.useSession.get().isPending;
						await delay();
						setCookie(context);
					},
				},
			});
			unsubscribe();

			expect(inOnSuccess).toBe(true);
			expect(current(client)).toEqual(signedIn);
			expectNoSettledSignedOut(states);
		});
	});

	it("keeps fetch plugin hooks and the session load when the per-call onSuccess throws", async () => {
		const { client, testUser, runWithUser, setCookie, persistWith } =
			await signedOutInstance();
		persistWith(async (context) => {
			await delay();
			setCookie(context);
		});
		await runWithUser(async () => {
			const { states, settled, unsubscribe } = recordSession(client);
			await settled();
			states.length = 0;

			const failure = new Error("callback failed");
			await expect(
				client.signIn.email({
					email: testUser.email,
					password: testUser.password,
					fetchOptions: {
						onSuccess() {
							throw failure;
						},
					},
				}),
			).rejects.toBe(failure);
			unsubscribe();

			expect(current(client)).toEqual(signedIn);
			expectNoSettledSignedOut(states);
		});
	});

	it("sends session fetches requested while the credentials are being persisted without committing them", async () => {
		const { client, testUser, runWithUser, setCookie, sessionRequests } =
			await signedOutInstance();
		await runWithUser(async () => {
			const { states, settled, unsubscribe } = recordSession(client);
			await settled();
			states.length = 0;
			const requestsBefore = sessionRequests();

			let refetched: SessionState | undefined;
			await client.signIn.email({
				email: testUser.email,
				password: testUser.password,
				fetchOptions: {
					async onSuccess(context) {
						// A focus refetch or a page mounting before the credentials exist.
						await client.useSession.get().refetch();
						refetched = current(client);
						setCookie(context);
					},
				},
			});
			unsubscribe();

			expect(sessionRequests()).toBe(requestsBefore + 2);
			expect(refetched).toMatchObject({
				isPending: true,
				signedIn: false,
			});
			expect(current(client)).toEqual(signedIn);
			expectNoSettledSignedOut(states);
		});
	});

	it("discards a session response requested before the sign-in succeeded", async () => {
		const { client, testUser, runWithUser, setCookie, beforeSessionResponse } =
			await signedOutInstance();
		await runWithUser(async () => {
			const { states, settled, unsubscribe } = recordSession(client);
			await settled();
			states.length = 0;

			let respond: (() => void) | undefined;
			beforeSessionResponse(
				() =>
					new Promise<void>((resolve) => {
						respond = resolve;
					}),
			);
			const stale = client.useSession.get().refetch();
			await vi.waitFor(() => expect(respond).toBeDefined());
			beforeSessionResponse(async () => {});

			await client.signIn.email({
				email: testUser.email,
				password: testUser.password,
				fetchOptions: {
					async onSuccess(context) {
						// The signed-out response lands while the credentials are persisted.
						respond?.();
						await stale;
						setCookie(context);
					},
				},
			});
			unsubscribe();

			expect(current(client)).toEqual(signedIn);
			expectNoSettledSignedOut(states);
		});
	});

	it("resolves without a session request while nothing reads the session, then loads it on the next read", async () => {
		const { client, testUser, runWithUser, setCookie, sessionRequests } =
			await signedOutInstance();
		await runWithUser(async () => {
			const requestsBefore = sessionRequests();
			await client.signIn.email({
				email: testUser.email,
				password: testUser.password,
				fetchOptions: {
					onSuccess: setCookie,
				},
			});
			expect(sessionRequests()).toBe(requestsBefore);

			const { states, settled, unsubscribe } = recordSession(client);
			await settled();
			unsubscribe();

			expect(states.at(-1)).toEqual(signedIn);
			expectNoSettledSignedOut(states);
		});
	});

	it("does not settle the old session on a store notification made during the sign-in", async () => {
		const { client, testUser, runWithUser, setCookie } =
			await signedOutInstance();
		await runWithUser(async () => {
			const { states, settled, unsubscribe } = recordSession(client);
			await settled();
			states.length = 0;

			await client.signIn.email({
				email: testUser.email,
				password: testUser.password,
				fetchOptions: {
					async onSuccess(context) {
						// Fetch plugins report persisted cookies the same way.
						client.$store.notify("$sessionSignal");
						await delay();
						setCookie(context);
					},
				},
			});
			unsubscribe();

			expect(current(client)).toEqual(signedIn);
			expectNoSettledSignedOut(states);
		});
	});

	it("resolves an auth call awaited inside another auth call's onSuccess", async () => {
		const { client, testUser, runWithUser, setCookie } =
			await signedOutInstance();
		await runWithUser(async () => {
			const { states, settled, unsubscribe } = recordSession(client);
			await settled();
			states.length = 0;

			let inner: SessionState | undefined;

			await client.signIn.email({
				email: testUser.email,
				password: testUser.password,
				fetchOptions: {
					async onSuccess() {
						await client.signIn.email({
							email: testUser.email,
							password: testUser.password,
							fetchOptions: {
								onSuccess: setCookie,
							},
						});
						inner = current(client);
					},
				},
			});
			unsubscribe();

			expect(inner).toEqual(signedIn);
			expect(current(client)).toEqual(signedIn);
			expectNoSettledSignedOut(states);
		});
	});

	it("resolves each overlapping auth call once the session reflects it", async () => {
		const { client, testUser, runWithUser, setCookie } =
			await signedOutInstance();
		await runWithUser(async () => {
			const { states, settled, unsubscribe } = recordSession(client);
			await settled();
			states.length = 0;

			let entered!: () => void;
			const inOnSuccess = new Promise<void>((resolve) => {
				entered = resolve;
			});
			let release!: () => void;
			const released = new Promise<void>((resolve) => {
				release = resolve;
			});
			const pending = client.signIn.email({
				email: testUser.email,
				password: testUser.password,
				fetchOptions: {
					async onSuccess(context) {
						entered();
						await released;
						setCookie(context);
					},
				},
			});
			await inOnSuccess;

			await client.signIn.email({
				email: testUser.email,
				password: testUser.password,
				fetchOptions: {
					onSuccess: setCookie,
				},
			});
			const first = current(client);
			release();
			await pending;
			unsubscribe();

			expect(first).toEqual(signedIn);
			expect(current(client)).toEqual(signedIn);
			expectNoSettledSignedOut(states);
		});
	});

	it("waits for the session request that replaced the one the auth call started", async () => {
		const { client, testUser, runWithUser, setCookie, beforeSessionResponse } =
			await signedOutInstance();
		await runWithUser(async () => {
			const { states, settled, unsubscribe } = recordSession(client);
			await settled();
			states.length = 0;

			let replaced = false;
			beforeSessionResponse(async () => {
				if (replaced) {
					await delay();
					return;
				}
				replaced = true;
				// A focus refetch lands while the sign-in waits for its request.
				void client.useSession.get().refetch();
			});
			await client.signIn.email({
				email: testUser.email,
				password: testUser.password,
				fetchOptions: {
					onSuccess: setCookie,
				},
			});
			unsubscribe();

			expect(current(client)).toEqual(signedIn);
			expectNoSettledSignedOut(states);
		});
	});

	it("settles signed out when the session request finds no session after the sign-in", async () => {
		const { client, testUser, runWithUser } = await signedOutInstance();
		await runWithUser(async () => {
			const { settled, unsubscribe } = recordSession(client);
			await settled();

			await client.signIn.email({
				email: testUser.email,
				password: testUser.password,
			});
			unsubscribe();

			expect(current(client)).toEqual({
				isPending: false,
				isRefetching: false,
				signedIn: false,
			});
		});
	});

	it("leaves the session untouched when the sign-in fails", async () => {
		const { client, testUser, runWithUser, sessionRequests } =
			await signedOutInstance();
		await runWithUser(async () => {
			const { states, settled, unsubscribe } = recordSession(client);
			await settled();
			states.length = 0;
			const requestsBefore = sessionRequests();

			await client.signIn.email({
				email: testUser.email,
				password: "wrong-password",
			});
			unsubscribe();

			expect(sessionRequests()).toBe(requestsBefore);
			expect(states).toEqual([]);
		});
	});
});

describe("session after a data change", () => {
	async function signedInInstance() {
		const instance = await getTestInstance();
		const { headers, runWithUser } = await instance.signInWithTestUser();
		return {
			...instance,
			headers,
			runWithUser,
		};
	}

	it("resolves once the session reflects the change", async () => {
		const { client, runWithUser } = await signedInInstance();
		await runWithUser(async () => {
			const { states, settled, unsubscribe } = recordSession(client);
			await settled();
			states.length = 0;

			await client.updateUser({ name: "Renamed" });
			const name = client.useSession.get().data?.user.name;
			unsubscribe();

			expect(name).toBe("Renamed");
			expect(states).not.toContainEqual(
				expect.objectContaining({ isPending: true }),
			);
		});
	});

	it("keeps the old value until the new one arrives when an earlier request lands during the change", async () => {
		const { client, runWithUser } = await signedInInstance();
		await runWithUser(async () => {
			const { states, settled, unsubscribe } = recordSession(client);
			await settled();
			states.length = 0;

			const earlier = client.useSession.get().refetch();
			await client.updateUser({
				name: "Renamed",
				fetchOptions: {
					async onSuccess() {
						await earlier;
					},
				},
			});
			const name = client.useSession.get().data?.user.name;
			unsubscribe();

			expect(name).toBe("Renamed");
			expect(states).not.toContainEqual(
				expect.objectContaining({ signedIn: false }),
			);
		});
	});

	it("settles a refetch made during the change while nothing reads the session", async () => {
		const { client, runWithUser } = await signedInInstance();
		await runWithUser(async () => {
			// Read through `value`, since `get()` would mount the atom.
			const session = client.$store.atoms.session!;
			await session.value.refetch();
			expect(session.value.data).not.toBeNull();

			await client.updateUser({
				name: "Renamed",
				fetchOptions: {
					async onSuccess() {
						await session.value.refetch();
					},
				},
			});

			expect(session.value).toMatchObject({
				isPending: false,
				isRefetching: false,
			});
			expect(session.value.data?.user.name).toBe("Renamed");
		});
	});
});
