import { describe, expect, it, onTestFinished, vi } from "vitest";
import { betterAuth } from "../../auth/full";
import { createAuthClient } from "../../client";
import { getTestInstance } from "../../test-utils/test-instance";
import { inferOrgAdditionalFields, organizationClient } from "./client";
import { organization } from "./organization";

describe("organization", () => {
	const auth = betterAuth({
		plugins: [
			organization({
				schema: {
					organization: {
						additionalFields: {
							newField: {
								type: "string",
							},
						},
					},
				},
			}),
		],
	});

	it("should infer additional fields", async () => {
		const client = createAuthClient({
			plugins: [
				organizationClient({
					schema: inferOrgAdditionalFields<typeof auth>(),
				}),
			],
			fetchOptions: {
				customFetchImpl: async () => new Response(),
			},
		});
		client.organization.create({
			name: "Test",
			slug: "test",
			newField: "123", //this should be allowed
			//@ts-expect-error - this field is not available
			unavailableField: "123", //this should be not allowed
		});
	});

	it("should infer filed when schema is provided", () => {
		const client = createAuthClient({
			plugins: [
				organizationClient({
					schema: inferOrgAdditionalFields({
						organization: {
							additionalFields: {
								newField: {
									type: "string",
								},
							},
						},
					}),
				}),
			],
			fetchOptions: {
				customFetchImpl: async () => new Response(),
			},
		});

		client.organization.create({
			name: "Test",
			slug: "test",
			newField: "123", //this should be allowed
			//@ts-expect-error - this field is not available
			unavailableField: "123", //this should be not allowed
		});
	});
});

/**
 * @see https://github.com/better-auth/better-auth/issues/9710
 */
it("refreshes the active organization after sign-in sets it in a session hook", async () => {
	let initialOrganizationId: string | undefined;
	const { auth, client, runWithUser, testUser, sessionSetter } =
		await getTestInstance(
			{
				plugins: [organization()],
				databaseHooks: {
					session: {
						create: {
							before: async (session) => ({
								data: {
									...session,
									activeOrganizationId: initialOrganizationId,
								},
							}),
						},
					},
				},
			},
			{ clientOptions: { plugins: [organizationClient()] } },
		);

	await runWithUser(testUser.email, testUser.password, async (headers) => {
		const organization = await auth.api.createOrganization({
			body: { name: "Test Workspace", slug: "test-workspace" },
			headers,
		});
		if (!organization) throw new Error("Organization was not created");
		initialOrganizationId = organization.id;
		headers.delete("cookie");

		const previousWindow = global.window;
		global.window = {} as Window & typeof globalThis;
		onTestFinished(() => {
			global.window = previousWindow;
		});

		const activeOrganization = client.$store.atoms.activeOrganization;
		if (!activeOrganization)
			throw new Error("Active organization atom missing");
		const unsubscribe = activeOrganization.subscribe(() => {});
		onTestFinished(unsubscribe);
		await vi.waitFor(() => {
			expect(activeOrganization.get().isPending).toBe(false);
		});
		expect(activeOrganization.get().data).toBeNull();

		const result = await client.signIn.email({
			email: testUser.email,
			password: testUser.password,
			fetchOptions: { onSuccess: sessionSetter(headers) },
		});
		expect(result.error).toBeNull();

		const fullOrganization = await auth.api.getFullOrganization({ headers });
		expect(fullOrganization?.id).toBe(initialOrganizationId);

		await vi.waitFor(() => {
			expect(activeOrganization.get().data?.id).toBe(initialOrganizationId);
		});
	});
});

describe("active organization during an auth change", () => {
	type OrganizationState = {
		isPending: boolean;
		isRefetching: boolean;
		id: string | undefined;
	};

	const delay = () => new Promise((resolve) => setTimeout(resolve, 5));

	async function organizationInstance(activeOrganizationId?: () => string) {
		let beforeOrganizationResponse: () => Promise<unknown> = async () => {};
		const instance = await getTestInstance(
			{
				plugins: [organization()],
				databaseHooks: {
					session: {
						create: {
							before: async (session) => ({
								data: {
									...session,
									activeOrganizationId: activeOrganizationId?.(),
								},
							}),
						},
					},
				},
			},
			{
				clientOptions: {
					plugins: [
						organizationClient(),
						{
							id: "organization-response",
							fetchPlugins: [
								{
									id: "organization-response",
									name: "organization-response",
									hooks: {
										async onResponse(context) {
											if (
												!context.request.url
													.toString()
													.includes("/organization/get-full-organization")
											)
												return;
											await beforeOrganizationResponse();
										},
									},
								},
							],
						},
					],
				},
			},
		);
		const previousWindow = global.window;
		global.window = {} as Window & typeof globalThis;
		onTestFinished(() => {
			global.window = previousWindow;
		});
		const activeOrganization = instance.client.$store.atoms.activeOrganization;
		if (!activeOrganization)
			throw new Error("Active organization atom missing");
		const current = (): OrganizationState => {
			const state = activeOrganization.get();
			return {
				isPending: state.isPending,
				isRefetching: state.isRefetching,
				id: state.data?.id,
			};
		};
		const record = async () => {
			const states: OrganizationState[] = [];
			const unsubscribe = activeOrganization.subscribe(() => {
				states.push(current());
			});
			onTestFinished(unsubscribe);
			await vi.waitFor(() => {
				expect(current()).toMatchObject({
					isPending: false,
					isRefetching: false,
				});
			});
			states.length = 0;
			return states;
		};
		return {
			...instance,
			activeOrganization,
			current,
			record,
			beforeOrganizationResponse(next: typeof beforeOrganizationResponse) {
				beforeOrganizationResponse = next;
			},
		};
	}

	it("keeps isPending false while refetching a missing active organization", async () => {
		const { runWithUser, testUser, activeOrganization, record } =
			await organizationInstance();
		await runWithUser(testUser.email, testUser.password, async () => {
			const states = await record();
			await activeOrganization.get().refetch();

			expect(states).toContainEqual({
				isPending: false,
				isRefetching: true,
				id: undefined,
			});
			expect(states).not.toContainEqual(
				expect.objectContaining({ isPending: true }),
			);
		});
	});

	it("keeps isPending false when an organization call changes data only", async () => {
		const { client, runWithUser, testUser, record } =
			await organizationInstance();
		await runWithUser(testUser.email, testUser.password, async () => {
			const states = await record();
			await client.organization.list();

			expect(states).not.toContainEqual(
				expect.objectContaining({ isPending: true }),
			);
		});
	});

	it("keeps isPending false when updating the user without an active organization", async () => {
		const { client, runWithUser, testUser, record } =
			await organizationInstance();
		await runWithUser(testUser.email, testUser.password, async () => {
			const session = client.$store.atoms.session!;
			onTestFinished(session.subscribe(() => {}));
			await vi.waitFor(() => {
				expect(session.get().data).not.toBeNull();
			});
			const states = await record();
			const result = await client.updateUser({ name: "Renamed" });

			expect(result.error).toBeNull();
			expect(states).not.toContainEqual(
				expect.objectContaining({ isPending: true }),
			);
		});
	});

	it("resolves setActive once the active organization reflects it", async () => {
		const { auth, client, runWithUser, testUser, current, record } =
			await organizationInstance();
		await runWithUser(testUser.email, testUser.password, async (headers) => {
			const target = await auth.api.createOrganization({
				body: {
					name: "Target",
					slug: "target",
					keepCurrentActiveOrganization: true,
				},
				headers,
			});
			if (!target) throw new Error("Organization was not created");
			await record();

			await client.organization.setActive({ organizationId: target.id });

			expect(current()).toEqual({
				isPending: false,
				isRefetching: false,
				id: target.id,
			});
		});
	});

	it("waits for the organization request that replaced the one setActive started", async () => {
		const {
			auth,
			client,
			runWithUser,
			testUser,
			activeOrganization,
			current,
			record,
			beforeOrganizationResponse,
		} = await organizationInstance();
		await runWithUser(testUser.email, testUser.password, async (headers) => {
			const target = await auth.api.createOrganization({
				body: {
					name: "Target",
					slug: "target",
					keepCurrentActiveOrganization: true,
				},
				headers,
			});
			if (!target) throw new Error("Organization was not created");
			await record();

			let replaced = false;
			beforeOrganizationResponse(async () => {
				if (replaced) return delay();
				replaced = true;
				void activeOrganization.get().refetch();
			});
			await client.organization.setActive({ organizationId: target.id });

			expect(current()).toEqual({
				isPending: false,
				isRefetching: false,
				id: target.id,
			});
		});
	});

	it("resolves each overlapping sign-in once the active organization has loaded", async () => {
		let organizationId = "";
		const {
			auth,
			client,
			runWithUser,
			testUser,
			sessionSetter,
			current,
			record,
		} = await organizationInstance(() => organizationId);
		await runWithUser(testUser.email, testUser.password, async (headers) => {
			const created = await auth.api.createOrganization({
				body: { name: "Workspace", slug: "workspace" },
				headers,
			});
			if (!created) throw new Error("Organization was not created");
			organizationId = created.id;
			headers.delete("cookie");
			await record();

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
						sessionSetter(headers)(context);
					},
				},
			});
			await inOnSuccess;

			await client.signIn.email({
				email: testUser.email,
				password: testUser.password,
				fetchOptions: {
					onSuccess: sessionSetter(headers),
				},
			});
			const first = current();
			release();
			const signedIn = await pending;

			expect(first).toEqual({
				isPending: false,
				isRefetching: false,
				id: organizationId,
			});
			expect(signedIn.error).toBeNull();
			expect(current()).toEqual({
				isPending: false,
				isRefetching: false,
				id: organizationId,
			});
		});
	});

	it("resolves sign-in once the active organization has loaded", async () => {
		let organizationId = "";
		const {
			auth,
			client,
			runWithUser,
			testUser,
			sessionSetter,
			current,
			record,
		} = await organizationInstance(() => organizationId);
		await runWithUser(testUser.email, testUser.password, async (headers) => {
			const created = await auth.api.createOrganization({
				body: { name: "Workspace", slug: "workspace" },
				headers,
			});
			if (!created) throw new Error("Organization was not created");
			organizationId = created.id;
			headers.delete("cookie");
			const states = await record();

			let refetched: OrganizationState | undefined;
			await client.signIn.email({
				email: testUser.email,
				password: testUser.password,
				fetchOptions: {
					async onSuccess(context) {
						// A read sent before the credentials are persisted.
						await client.$store.atoms.activeOrganization!.get().refetch();
						refetched = current();
						sessionSetter(headers)(context);
					},
				},
			});

			expect(refetched).toMatchObject({
				isPending: true,
				id: undefined,
			});
			expect(current()).toEqual({
				isPending: false,
				isRefetching: false,
				id: organizationId,
			});
			// A settled missing organization would bounce guarded pages.
			expect(states).not.toContainEqual({
				isPending: false,
				isRefetching: false,
				id: undefined,
			});
		});
	});
});
