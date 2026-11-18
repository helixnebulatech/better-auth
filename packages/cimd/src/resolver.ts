import type { GenericEndpointContext } from "@better-auth/core";
import { BetterAuthError } from "@better-auth/core/error";
import type {
	OAuthClientMetadata,
	OAuthOptions,
	SchemaClient,
	Scope,
} from "@better-auth/oauth-provider";
import { getExtensionClientMetadataFields } from "@better-auth/oauth-provider/internal";
import { toExpJWT } from "better-auth/plugins";
import { APIError } from "better-call";
import type { MetadataDocumentResponseCacheHeaders } from "./client-store";
import {
	assertClientIdUrlFetchable,
	FETCH_TIMEOUT_MS,
	fetchClientMetadataDocument,
	isClientCurrentWithMetadata,
	persistMetadataDocumentClient,
} from "./client-store";
import type {
	CimdMetadataResolution,
	CimdMetadataResolver,
	CimdMetadataResolverOptions,
	CimdOptions,
} from "./types";
import { isCimdClientIdUrlCandidate } from "./validate-metadata-document";

const FETCH_BUDGET_WINDOW_MS = 60_000;
// A request that joins a fetch stops waiting for it after twice the fetch
// timeout, which the request that started the fetch enforces itself. A fetch
// permit is leased for the same time.
const JOINED_FETCH_WAIT_MS = FETCH_TIMEOUT_MS * 2;
const DEFAULT_METADATA_FETCH_POLICY = {
	minimumFetchInterval: 1,
	maximumConcurrentFetches: 16,
	maximumConcurrentFetchesPerOrigin: 4,
	maximumFetchesPerMinute: 120,
	maximumFetchesPerOriginPerMinute: 30,
} as const;

type CimdResolver = (
	ctx: GenericEndpointContext,
	clientId: string,
	existing: SchemaClient<Scope[]> | null,
) => Promise<SchemaClient<Scope[]> | null>;

interface CimdMetadataCacheEntry {
	metadata: OAuthClientMetadata;
	expiresAt: number;
	etag?: string;
	lastModified?: string;
	responseCacheHeaders: MetadataDocumentResponseCacheHeaders;
}

interface FetchedMetadata {
	metadata: OAuthClientMetadata;
	/** The cache entry the fetch stored, or null when the response is not cacheable. */
	entry: CimdMetadataCacheEntry | null;
}

interface InFlightMetadataFetch {
	fetched: Promise<FetchedMetadata>;
	/** When the fetch took its permit, which is leased for `JOINED_FETCH_WAIT_MS`. */
	startedAtMs: number;
	/** Retires the fetch and returns its permit. Calling it again does nothing. */
	retire: () => void;
	/**
	 * Whether the fetch was retired and its outcome is not used. A retired
	 * fetch's document may be older than the document of the fetch that
	 * replaced it, so nobody returns it, and its failure is not reported.
	 * A fetch retired by the lease with no replacement is used when it
	 * answers late.
	 */
	isDiscarded: () => boolean;
}

/**
 * A resolution from a resolver that a discovery owns. It can drop its document
 * when the discovery cannot save the client.
 */
interface OwnedMetadataResolution extends CimdMetadataResolution {
	/**
	 * Drop the cached document, so the next request fetches it again after the
	 * per-client minimum interval.
	 */
	discard(): void;
}

type OwnedMetadataResolver = (
	ctx: GenericEndpointContext,
	clientId: string,
) => Promise<OwnedMetadataResolution | null>;

interface ResolvedMetadataFetchPolicy {
	minimumFetchIntervalMs: number;
	maximumConcurrentFetches: number;
	maximumConcurrentFetchesPerOrigin: number;
	maximumFetchesPerMinute: number;
	maximumFetchesPerOriginPerMinute: number;
}

interface OriginFetchState {
	activeFetchCount: number;
	fetchStartTimesMs: number[];
}

function invalidClient(description: string): APIError {
	return new APIError("BAD_REQUEST", {
		error: "invalid_client",
		error_description: description,
	});
}

function createMetadataFetchUnavailableError(description: string): APIError {
	return new APIError("TOO_MANY_REQUESTS", {
		error: "temporarily_unavailable",
		error_description: description,
	});
}

function parseDurationMs(value: number | string, optionName: string): number {
	if (typeof value === "number") {
		if (!Number.isFinite(value) || value < 0) {
			throw new BetterAuthError(
				`cimd metadataFetchPolicy.${optionName} must be a non-negative number of seconds or duration string`,
			);
		}
		return value * 1000;
	}
	try {
		const nowSeconds = Math.floor(Date.now() / 1000);
		const durationMs = (toExpJWT(value, nowSeconds) - nowSeconds) * 1000;
		if (!Number.isFinite(durationMs) || durationMs < 0) {
			throw new Error("negative duration");
		}
		return durationMs;
	} catch {
		throw new BetterAuthError(
			`cimd metadataFetchPolicy.${optionName} must be a non-negative number of seconds or duration string`,
		);
	}
}

function requirePositiveInteger(value: number, optionName: string): number {
	if (!Number.isInteger(value) || value < 1) {
		throw new BetterAuthError(
			`cimd metadataFetchPolicy.${optionName} must be a positive integer`,
		);
	}
	return value;
}

function resolveMetadataFetchPolicy(
	options: CimdMetadataResolverOptions,
): ResolvedMetadataFetchPolicy {
	const policy = options.metadataFetchPolicy;
	return {
		minimumFetchIntervalMs: parseDurationMs(
			policy?.minimumFetchInterval ??
				DEFAULT_METADATA_FETCH_POLICY.minimumFetchInterval,
			"minimumFetchInterval",
		),
		maximumConcurrentFetches: requirePositiveInteger(
			policy?.maximumConcurrentFetches ??
				DEFAULT_METADATA_FETCH_POLICY.maximumConcurrentFetches,
			"maximumConcurrentFetches",
		),
		maximumConcurrentFetchesPerOrigin: requirePositiveInteger(
			policy?.maximumConcurrentFetchesPerOrigin ??
				DEFAULT_METADATA_FETCH_POLICY.maximumConcurrentFetchesPerOrigin,
			"maximumConcurrentFetchesPerOrigin",
		),
		maximumFetchesPerMinute: requirePositiveInteger(
			policy?.maximumFetchesPerMinute ??
				DEFAULT_METADATA_FETCH_POLICY.maximumFetchesPerMinute,
			"maximumFetchesPerMinute",
		),
		maximumFetchesPerOriginPerMinute: requirePositiveInteger(
			policy?.maximumFetchesPerOriginPerMinute ??
				DEFAULT_METADATA_FETCH_POLICY.maximumFetchesPerOriginPerMinute,
			"maximumFetchesPerOriginPerMinute",
		),
	};
}

function pruneFetchStartTimesMs(
	fetchStartTimesMs: number[],
	nowMs: number,
): void {
	const windowStart = nowMs - FETCH_BUDGET_WINDOW_MS;
	let firstRetainedIndex = 0;
	while (
		firstRetainedIndex < fetchStartTimesMs.length &&
		(fetchStartTimesMs[firstRetainedIndex] as number) <= windowStart
	) {
		firstRetainedIndex += 1;
	}
	if (firstRetainedIndex > 0) {
		fetchStartTimesMs.splice(0, firstRetainedIndex);
	}
}

function resolveMetadataRevalidationIntervalMs(
	metadataRevalidationInterval: number | string,
	nowMs: number,
): number {
	if (typeof metadataRevalidationInterval === "number") {
		return Math.max(0, metadataRevalidationInterval * 1000);
	}
	const nowSeconds = Math.floor(nowMs / 1000);
	return Math.max(
		0,
		(toExpJWT(metadataRevalidationInterval, nowSeconds) - nowSeconds) * 1000,
	);
}

function parseCacheControl(value: string | undefined): {
	directives: Map<string, string | true>;
	duplicates: Set<string>;
} {
	const directives = new Map<string, string | true>();
	const duplicates = new Set<string>();
	for (const rawDirective of value?.split(",") ?? []) {
		const [rawName, ...rawValue] = rawDirective.trim().split("=");
		const name = rawName?.toLowerCase();
		if (!name) continue;
		if (directives.has(name)) duplicates.add(name);
		const joinedValue = rawValue.join("=").trim();
		directives.set(
			name,
			joinedValue ? joinedValue.replace(/^"|"$/g, "") : true,
		);
	}
	return { directives, duplicates };
}

function parseNonNegativeSeconds(
	value: string | true | undefined,
): number | null {
	if (typeof value !== "string" || !/^\d+$/.test(value)) return null;
	const seconds = Number(value);
	return Number.isSafeInteger(seconds) ? seconds : null;
}

function computeExpiresAt(
	cacheHeaders: MetadataDocumentResponseCacheHeaders,
	metadataRevalidationInterval: number | string,
	nowMs: number,
): { cacheable: boolean; expiresAt: number } {
	const { directives, duplicates } = parseCacheControl(
		cacheHeaders.cacheControl,
	);
	const variesByEverything = cacheHeaders.vary
		?.split(",")
		.some((field) => field.trim() === "*");
	if (
		directives.has("no-store") ||
		directives.has("private") ||
		variesByEverything
	) {
		return { cacheable: false, expiresAt: nowMs };
	}

	const operatorLifetime = resolveMetadataRevalidationIntervalMs(
		metadataRevalidationInterval,
		nowMs,
	);
	if (directives.has("no-cache")) {
		return { cacheable: true, expiresAt: nowMs };
	}

	const ageSeconds = parseNonNegativeSeconds(cacheHeaders.age) ?? 0;
	const responseDate = cacheHeaders.date
		? Date.parse(cacheHeaders.date)
		: nowMs;
	const apparentAge = Number.isFinite(responseDate)
		? Math.max(0, nowMs - responseDate)
		: 0;
	const currentAge = Math.max(apparentAge, ageSeconds * 1000);

	let originLifetime: number | null = null;
	const hasSharedMaxAge = directives.has("s-maxage");
	const sharedMaxAge = parseNonNegativeSeconds(directives.get("s-maxage"));
	const hasMaxAge = directives.has("max-age");
	const privateMaxAge = parseNonNegativeSeconds(directives.get("max-age"));
	const applicableFreshnessIsInvalid = hasSharedMaxAge
		? sharedMaxAge === null || duplicates.has("s-maxage")
		: hasMaxAge && (privateMaxAge === null || duplicates.has("max-age"));
	const maxAge = hasSharedMaxAge ? sharedMaxAge : privateMaxAge;
	if (applicableFreshnessIsInvalid) {
		originLifetime = 0;
	} else if (maxAge !== null) {
		originLifetime = Math.max(0, maxAge * 1000 - currentAge);
	} else if (cacheHeaders.expires) {
		const expires = Date.parse(cacheHeaders.expires);
		if (Number.isFinite(expires)) {
			const dateBase = Number.isFinite(responseDate) ? responseDate : nowMs;
			originLifetime = Math.max(0, expires - dateBase - currentAge);
		}
	}

	return {
		cacheable: true,
		expiresAt:
			nowMs + Math.min(operatorLifetime, originLifetime ?? operatorLifetime),
	};
}

function mergeCacheHeaders(
	previous: MetadataDocumentResponseCacheHeaders,
	revalidated: MetadataDocumentResponseCacheHeaders,
): MetadataDocumentResponseCacheHeaders {
	return {
		cacheControl: revalidated.cacheControl ?? previous.cacheControl,
		vary: revalidated.vary ?? previous.vary,
		expires: revalidated.expires ?? previous.expires,
		date: revalidated.date ?? previous.date,
		age: revalidated.age ?? previous.age,
		etag: revalidated.etag ?? previous.etag,
		lastModified: revalidated.lastModified ?? previous.lastModified,
	};
}

function createCacheEntry(
	metadata: OAuthClientMetadata,
	cacheHeaders: MetadataDocumentResponseCacheHeaders,
	metadataRevalidationInterval: number | string,
	nowMs: number,
): CimdMetadataCacheEntry | null {
	const freshness = computeExpiresAt(
		cacheHeaders,
		metadataRevalidationInterval,
		nowMs,
	);
	if (!freshness.cacheable) return null;
	return {
		metadata,
		expiresAt: freshness.expiresAt,
		etag: cacheHeaders.etag,
		lastModified: cacheHeaders.lastModified,
		responseCacheHeaders: cacheHeaders,
	};
}

function getOAuthProviderOptions(
	ctx: GenericEndpointContext,
): OAuthOptions<Scope[]> {
	const provider = ctx.context.getPlugin("oauth-provider");
	if (!provider) {
		throw new BetterAuthError(
			"cimd discovery invoked without the oauth-provider plugin installed",
		);
	}
	return provider.options as OAuthOptions<Scope[]>;
}

/**
 * Build the metadata resolver behind {@link createCimdMetadataResolver}. Its
 * resolutions can also drop their document, which only a discovery that owns
 * the resolver does.
 *
 * Concurrent requests for one client share a single fetch. The document each
 * request receives is its own copy, and the caller saves it with that
 * request's context. A request waits at most `JOINED_FETCH_WAIT_MS` for each
 * fetch it joins and then fetches for itself, so a request that the runtime
 * ended cannot stall the others.
 */
function createMetadataResolver(
	options: CimdMetadataResolverOptions,
): OwnedMetadataResolver {
	const metadataRevalidationInterval =
		options.metadataRevalidationInterval ?? "60m";
	const maxCacheEntries = options.maxCacheEntries ?? 1_000;
	if (!Number.isInteger(maxCacheEntries) || maxCacheEntries < 1) {
		throw new BetterAuthError(
			"cimd maxCacheEntries must be a positive integer",
		);
	}
	const fetchPolicy = resolveMetadataFetchPolicy(options);
	const metadataCache = new Map<string, CimdMetadataCacheEntry>();
	const inFlightFetchByClientId = new Map<string, InFlightMetadataFetch>();
	const lastFetchStartAtMsByClientId = new Map<string, number>();
	const fetchStateByOrigin = new Map<string, OriginFetchState>();
	const globalFetchStartTimesMs: number[] = [];
	let activeFetchCount = 0;

	const readCacheEntry = (clientId: string) => {
		const entry = metadataCache.get(clientId);
		if (!entry) return undefined;
		metadataCache.delete(clientId);
		metadataCache.set(clientId, entry);
		return entry;
	};

	const storeCacheEntry = (clientId: string, entry: CimdMetadataCacheEntry) => {
		metadataCache.delete(clientId);
		while (metadataCache.size >= maxCacheEntries) {
			const leastRecentlyUsedClientId = metadataCache.keys().next().value;
			if (typeof leastRecentlyUsedClientId !== "string") break;
			metadataCache.delete(leastRecentlyUsedClientId);
		}
		metadataCache.set(clientId, entry);
	};

	const ensureClientFetchStateCapacity = (clientId: string, nowMs: number) => {
		if (lastFetchStartAtMsByClientId.has(clientId)) return;
		while (lastFetchStartAtMsByClientId.size >= maxCacheEntries) {
			let evicted = false;
			for (const [
				candidateClientId,
				candidateLastFetchStartAtMs,
			] of lastFetchStartAtMsByClientId) {
				if (inFlightFetchByClientId.has(candidateClientId)) {
					continue;
				}
				if (
					fetchPolicy.minimumFetchIntervalMs > 0 &&
					nowMs - candidateLastFetchStartAtMs <
						fetchPolicy.minimumFetchIntervalMs
				) {
					continue;
				}
				lastFetchStartAtMsByClientId.delete(candidateClientId);
				evicted = true;
				break;
			}
			if (evicted) continue;
			throw createMetadataFetchUnavailableError(
				"metadata fetch client state is at capacity",
			);
		}
	};

	const readOrCreateOriginFetchState = (
		origin: string,
		nowMs: number,
	): OriginFetchState => {
		const existingState = fetchStateByOrigin.get(origin);
		if (existingState) {
			pruneFetchStartTimesMs(existingState.fetchStartTimesMs, nowMs);
			fetchStateByOrigin.delete(origin);
			fetchStateByOrigin.set(origin, existingState);
			return existingState;
		}

		while (fetchStateByOrigin.size >= maxCacheEntries) {
			let evicted = false;
			for (const [candidateOrigin, candidateState] of fetchStateByOrigin) {
				pruneFetchStartTimesMs(candidateState.fetchStartTimesMs, nowMs);
				if (
					candidateState.activeFetchCount > 0 ||
					candidateState.fetchStartTimesMs.length > 0
				) {
					continue;
				}
				fetchStateByOrigin.delete(candidateOrigin);
				evicted = true;
				break;
			}
			if (evicted) continue;
			throw createMetadataFetchUnavailableError(
				"metadata fetch origin state is at capacity",
			);
		}

		const createdState = {
			activeFetchCount: 0,
			fetchStartTimesMs: [],
		};
		fetchStateByOrigin.set(origin, createdState);
		return createdState;
	};

	// A fetch whose request the runtime ended may never settle, and then never
	// returns its permit. A retired fetch leaves the in-flight map, its pacing
	// record and permit are returned, and it can no longer publish or record a
	// failure, so later requests fetch again.
	const retireFetch = (clientId: string, inFlight: InFlightMetadataFetch) => {
		if (inFlightFetchByClientId.get(clientId) === inFlight) {
			inFlightFetchByClientId.delete(clientId);
			lastFetchStartAtMsByClientId.delete(clientId);
		}
		inFlight.retire();
	};

	const acquireMetadataFetchPermit = (clientId: string): (() => void) => {
		const nowMs = Date.now();
		// Permits are leased, so a request for any client can take back the slots
		// that fetches which never settled still hold.
		for (const [inFlightClientId, inFlight] of inFlightFetchByClientId) {
			if (nowMs - inFlight.startedAtMs >= JOINED_FETCH_WAIT_MS) {
				retireFetch(inFlightClientId, inFlight);
			}
		}
		const lastFetchStartAtMs = lastFetchStartAtMsByClientId.get(clientId);
		if (
			fetchPolicy.minimumFetchIntervalMs > 0 &&
			lastFetchStartAtMs !== undefined &&
			nowMs - lastFetchStartAtMs < fetchPolicy.minimumFetchIntervalMs
		) {
			throw createMetadataFetchUnavailableError(
				"metadata document fetch is within the per-client minimum interval",
			);
		}
		ensureClientFetchStateCapacity(clientId, nowMs);

		const origin = new URL(clientId).origin;
		const originState = readOrCreateOriginFetchState(origin, nowMs);

		pruneFetchStartTimesMs(globalFetchStartTimesMs, nowMs);
		if (activeFetchCount >= fetchPolicy.maximumConcurrentFetches) {
			throw createMetadataFetchUnavailableError(
				"global metadata fetch concurrency limit exceeded",
			);
		}
		if (
			originState.activeFetchCount >=
			fetchPolicy.maximumConcurrentFetchesPerOrigin
		) {
			throw createMetadataFetchUnavailableError(
				"metadata fetch concurrency limit exceeded for client origin",
			);
		}
		if (globalFetchStartTimesMs.length >= fetchPolicy.maximumFetchesPerMinute) {
			throw createMetadataFetchUnavailableError(
				"global metadata fetch rate limit exceeded",
			);
		}
		if (
			originState.fetchStartTimesMs.length >=
			fetchPolicy.maximumFetchesPerOriginPerMinute
		) {
			throw createMetadataFetchUnavailableError(
				"metadata fetch rate limit exceeded for client origin",
			);
		}

		lastFetchStartAtMsByClientId.delete(clientId);
		lastFetchStartAtMsByClientId.set(clientId, nowMs);
		globalFetchStartTimesMs.push(nowMs);
		originState.fetchStartTimesMs.push(nowMs);
		activeFetchCount += 1;
		originState.activeFetchCount += 1;

		let released = false;
		return () => {
			if (released) return;
			released = true;
			activeFetchCount -= 1;
			originState.activeFetchCount -= 1;
		};
	};

	const toResolution = (
		clientId: string,
		{ metadata, entry }: FetchedMetadata,
		fromCache: boolean,
	): OwnedMetadataResolution => ({
		metadata: structuredClone(metadata),
		fromCache,
		discard() {
			if (entry && metadataCache.get(clientId) === entry) {
				metadataCache.delete(clientId);
			}
			lastFetchStartAtMsByClientId.delete(clientId);
			lastFetchStartAtMsByClientId.set(clientId, Date.now());
		},
	});

	// A request that joined a fetch that does not settle in time retires it.
	const joinFetch = async (
		clientId: string,
		inFlight: InFlightMetadataFetch,
	): Promise<FetchedMetadata | undefined> => {
		let giveUp: (value: undefined) => void = () => {};
		const gaveUp = new Promise<undefined>((resolve) => {
			giveUp = resolve;
		});
		const timer = setTimeout(giveUp, JOINED_FETCH_WAIT_MS);
		let fetched: FetchedMetadata | undefined;
		try {
			fetched = await Promise.race([inFlight.fetched, gaveUp]);
		} catch (error) {
			if (inFlight.isDiscarded()) return undefined;
			throw error;
		} finally {
			clearTimeout(timer);
		}
		if (fetched === undefined) {
			retireFetch(clientId, inFlight);
			return undefined;
		}
		return inFlight.isDiscarded() ? undefined : fetched;
	};

	const readFreshEntry = (clientId: string) => {
		const entry = readCacheEntry(clientId);
		return entry && entry.expiresAt > Date.now() ? entry : undefined;
	};

	// Resolves to `undefined` when the fetch was retired before it settled and
	// its outcome, a document or a failure, is not used.
	const startFetch = async (
		ctx: GenericEndpointContext,
		clientId: string,
		cachedEntry: CimdMetadataCacheEntry | undefined,
		oauthOptions: OAuthOptions<Scope[]>,
	): Promise<FetchedMetadata | undefined> => {
		const releaseMetadataFetchPermit = acquireMetadataFetchPermit(clientId);
		let retired = false;
		let acceptedLate = false;
		const fetchPromise = (async (): Promise<FetchedMetadata> => {
			const fetched = await fetchClientMetadataDocument(
				ctx,
				clientId,
				options,
				cachedEntry
					? {
							etag: cachedEntry.etag,
							lastModified: cachedEntry.lastModified,
						}
					: undefined,
				getExtensionClientMetadataFields(oauthOptions),
			);

			if (fetched.status === "not-modified" && !cachedEntry) {
				throw invalidClient(
					"Metadata document returned 304 without a validated cached document",
				);
			}

			const metadata =
				fetched.status === "modified"
					? fetched.metadata
					: (cachedEntry as CimdMetadataCacheEntry).metadata;
			const cacheHeaders =
				fetched.status === "modified"
					? fetched.cacheHeaders
					: mergeCacheHeaders(
							(cachedEntry as CimdMetadataCacheEntry).responseCacheHeaders,
							fetched.cacheHeaders,
						);
			const nextEntry = createCacheEntry(
				metadata,
				cacheHeaders,
				metadataRevalidationInterval,
				Date.now(),
			);
			// A retired fetch leaves the cache and pacing to the fetch that replaced
			// it. When nothing replaced it, its document is the newest there is, so
			// it is accepted instead of spending another fetch on the same document.
			if (
				retired &&
				!inFlightFetchByClientId.has(clientId) &&
				metadataCache.get(clientId) === cachedEntry
			) {
				acceptedLate = true;
			}
			if (!retired || acceptedLate) {
				if (nextEntry) {
					storeCacheEntry(clientId, nextEntry);
				} else {
					metadataCache.delete(clientId);
				}
				// Successful fetches are governed by HTTP freshness and origin/global
				// budgets. Keep the per-client interval only as failed-fetch backoff.
				lastFetchStartAtMsByClientId.delete(clientId);
			}
			return { metadata, entry: nextEntry };
		})();
		const inFlight: InFlightMetadataFetch = {
			fetched: fetchPromise,
			startedAtMs: Date.now(),
			retire() {
				retired = true;
				releaseMetadataFetchPermit();
			},
			isDiscarded: () => retired && !acceptedLate,
		};
		inFlightFetchByClientId.set(clientId, inFlight);
		try {
			const fetched = await fetchPromise;
			return inFlight.isDiscarded() ? undefined : fetched;
		} catch (error) {
			if (inFlight.isDiscarded()) return undefined;
			if (!retired) {
				lastFetchStartAtMsByClientId.delete(clientId);
				lastFetchStartAtMsByClientId.set(clientId, Date.now());
			}
			throw error;
		} finally {
			if (inFlightFetchByClientId.get(clientId) === inFlight) {
				inFlightFetchByClientId.delete(clientId);
			}
			releaseMetadataFetchPermit();
		}
	};

	return async (ctx, clientId) => {
		if (!isCimdClientIdUrlCandidate(clientId)) {
			return null;
		}

		const oauthOptions = getOAuthProviderOptions(ctx);
		const initialEntry = readFreshEntry(clientId);
		if (initialEntry) {
			return toResolution(
				clientId,
				{ metadata: initialEntry.metadata, entry: initialEntry },
				true,
			);
		}

		// Every caller that would fetch or join a fetch evaluates the URL policy
		// itself, before any permit is taken: refused URLs never spend the fetch
		// budget, and a context-dependent policy is never skipped by coalescing.
		await assertClientIdUrlFetchable(ctx, clientId, options);

		// A fetch that was retired before it settled is not used: the fetch that
		// replaced it may hold a newer document, so the caller looks again.
		while (true) {
			// Another caller may have cached or started a fetch while the policy ran
			// or the caller waited. A document that landed in that window is newer
			// than anything the caller read before it, so it is reported as fetched,
			// not as a cache hit.
			const cachedEntry = readCacheEntry(clientId);
			if (cachedEntry && cachedEntry.expiresAt > Date.now()) {
				return toResolution(
					clientId,
					{ metadata: cachedEntry.metadata, entry: cachedEntry },
					false,
				);
			}

			const sharedFetch = inFlightFetchByClientId.get(clientId);
			const fetched = sharedFetch
				? await joinFetch(clientId, sharedFetch)
				: await startFetch(ctx, clientId, cachedEntry, oauthOptions);
			if (fetched) return toResolution(clientId, fetched, false);
		}
	};
}

/**
 * Build a resolver that fetches, validates, and caches Client ID Metadata
 * Documents, and saves nothing.
 *
 * The cache, fetch budgets, and in-flight fetches live in this closure. Pass
 * the result to `cimd({ metadataResolver })` to share them between discoveries
 * that are created per request, as a runtime whose database handle belongs to
 * one request needs. Without it, each plugin instance owns its own resolver, so
 * separate `cimd()` instances never share trust state or conditional validators.
 *
 * Concurrent requests for one client share a single fetch. The document each
 * request receives is its own copy, and the caller saves it with that
 * request's context. A request waits at most 10 seconds for each fetch it
 * joins and then fetches for itself, so a request that the runtime ended
 * cannot stall the others.
 *
 * The resolver carries `fetchClientMetadataResource`, and a discovery that uses
 * it fetches discovery-owned resources such as `jwks_uri` with that transport.
 */
export function createCimdMetadataResolver(
	options: CimdMetadataResolverOptions,
): CimdMetadataResolver {
	const resolveMetadata = createMetadataResolver(options);
	return Object.assign(
		async (
			context: GenericEndpointContext,
			clientId: string,
		): Promise<CimdMetadataResolution | null> => {
			const resolution = await resolveMetadata(context, clientId);
			return (
				resolution && {
					metadata: resolution.metadata,
					fromCache: resolution.fromCache,
				}
			);
		},
		{ fetchClientMetadataResource: options.fetchClientMetadataResource },
	);
}

const METADATA_RESOLVER_OPTION_NAMES = [
	"fetchClientMetadataResource",
	"isMetadataDocumentUrlAllowed",
	"maxCacheEntries",
	"metadataFetchPolicy",
	"metadataProfile",
	"metadataRevalidationInterval",
	"originBoundFields",
] as const satisfies readonly (keyof CimdMetadataResolverOptions)[];

/**
 * Build the discovery's resolver: it asks the metadata resolver for the
 * validated document, then saves the client with the request's own context.
 *
 * The coalesced fetch never saves anything, so one request's database context
 * or failure cannot reach another request that joined the same fetch.
 */
export function createCimdResolver(cimdOptions: CimdOptions): CimdResolver {
	const sharedResolver = cimdOptions.metadataResolver;
	if (!sharedResolver) {
		const resolveMetadata = createMetadataResolver(cimdOptions);
		return async (ctx, clientId, existingClient) => {
			const resolution = await resolveMetadata(ctx, clientId);
			if (!resolution) return null;

			// An owned resolver only caches what its own discovery fetched, so a
			// cache hit vouches for the stored row. No request waits for another
			// request's save, so a hit that arrives while a refresh is still saving
			// gets the row as it was.
			if (resolution.fromCache && existingClient) return existingClient;

			try {
				return await persistMetadataDocumentClient(
					ctx,
					clientId,
					resolution.metadata,
					cimdOptions,
					getOAuthProviderOptions(ctx),
					existingClient ?? undefined,
				);
			} catch (error) {
				if (!resolution.fromCache) resolution.discard();
				throw error;
			}
		};
	}

	const misplaced = METADATA_RESOLVER_OPTION_NAMES.filter(
		(name) => cimdOptions[name] !== undefined,
	);
	if (misplaced.length > 0) {
		throw new BetterAuthError(
			`cimd ${misplaced.join(", ")} cannot be set together with metadataResolver. Pass them to createCimdMetadataResolver instead.`,
		);
	}
	// Discovery-owned resources such as `jwks_uri` are fetched with the
	// resolver's transport, so a resolver without one must not get this far.
	if (typeof sharedResolver.fetchClientMetadataResource !== "function") {
		throw new BetterAuthError(
			"cimd metadataResolver has no fetchClientMetadataResource. Create it with createCimdMetadataResolver.",
		);
	}

	return async (ctx, clientId, existingClient) => {
		const resolution = await sharedResolver(ctx, clientId);
		if (!resolution) return null;

		const oauthOptions = getOAuthProviderOptions(ctx);
		// A resolver shared with other discoveries can hold a document that was
		// saved through another database, so a cache hit cannot vouch for this
		// database's row. A failed save keeps the document cached: the next
		// request that finds its stored client out of date saves it again.
		if (
			resolution.fromCache &&
			existingClient &&
			isClientCurrentWithMetadata(
				existingClient,
				resolution.metadata,
				oauthOptions,
			)
		) {
			return existingClient;
		}

		return persistMetadataDocumentClient(
			ctx,
			clientId,
			resolution.metadata,
			cimdOptions,
			oauthOptions,
			existingClient ?? undefined,
		);
	};
}
