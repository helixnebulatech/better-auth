import type { GenericEndpointContext } from "@better-auth/core";
import type {
	ClientMetadataResourceFetch,
	OAuthClientMetadata,
	SchemaClient,
	Scope,
} from "@better-auth/oauth-provider";

export type CimdMetadataProfile = "mcp-2026-07-28";

/** A validated Client ID Metadata Document, ready to be persisted. */
export interface CimdMetadataResolution {
	/** Validated document. A copy: changing it does not change the cache. */
	metadata: OAuthClientMetadata;
	/**
	 * Whether an unexpired cache entry answered at once, so the request neither
	 * fetched nor waited for a fetch. It is `false` when the request fetched the
	 * document, joined a fetch, or found a document another request cached while
	 * the URL policy ran.
	 */
	fromCache: boolean;
}

/**
 * Fetches, validates, and caches Client ID Metadata Documents without touching
 * the database. Create one with {@link createCimdMetadataResolver} and pass it
 * to `cimd({ metadataResolver })`.
 *
 * Calling it returns `null` when `clientId` is not a Client ID Metadata
 * Document URL. The context is the request's own: it reaches
 * `isMetadataDocumentUrlAllowed` and supplies the OAuth provider's extension
 * fields, and nothing is written through it.
 */
export interface CimdMetadataResolver {
	(
		context: GenericEndpointContext,
		clientId: string,
	): Promise<CimdMetadataResolution | null>;
	/**
	 * The transport the resolver fetches documents with. A discovery that uses
	 * the resolver also fetches its other metadata resources, such as
	 * `jwks_uri`, with it.
	 */
	readonly fetchClientMetadataResource: ClientMetadataResourceFetch;
}

export interface CimdClientCreatedEvent {
	/** Newly persisted discovery-owned OAuth client. */
	client: SchemaClient<Scope[]>;
	/** Validated Client ID Metadata Document that produced the client. */
	clientMetadataDocument: OAuthClientMetadata;
	/** Better Auth endpoint context for the discovery request. */
	context: GenericEndpointContext;
}

export interface CimdClientRefreshedEvent {
	/** Discovery-owned OAuth client after metadata reconciliation. */
	client: SchemaClient<Scope[]>;
	/** Client state captured before metadata reconciliation. */
	previousClient: SchemaClient<Scope[]>;
	/** Validated Client ID Metadata Document used for reconciliation. */
	clientMetadataDocument: OAuthClientMetadata;
	/** Better Auth endpoint context for the discovery request. */
	context: GenericEndpointContext;
}

export interface CimdMetadataFetchPolicy {
	/**
	 * Minimum time before retrying a failed metadata fetch for one exact client
	 * ID. Successful fetches are governed by HTTP freshness and the origin/global
	 * fetch budgets. Numeric values are seconds. Set to `0` to disable failed-fetch
	 * pacing.
	 *
	 * @default 1
	 */
	minimumFetchInterval?: number | string;
	/**
	 * Maximum metadata fetches in flight across the plugin instance.
	 *
	 * @default 16
	 */
	maximumConcurrentFetches?: number;
	/**
	 * Maximum metadata fetches in flight for one URL origin.
	 *
	 * @default 4
	 */
	maximumConcurrentFetchesPerOrigin?: number;
	/**
	 * Maximum fetch starts in a rolling 60-second window across the
	 * plugin instance.
	 *
	 * @default 120
	 */
	maximumFetchesPerMinute?: number;
	/**
	 * Maximum fetch starts in a rolling 60-second window for one URL
	 * origin.
	 *
	 * @default 30
	 */
	maximumFetchesPerOriginPerMinute?: number;
}

/**
 * Options that govern how metadata documents are fetched, validated, and
 * cached. Pass them to `cimd()`, or to {@link createCimdMetadataResolver} when
 * several plugin instances share one resolver.
 */
export interface CimdMetadataResolverOptions {
	/**
	 * Fetch transport for metadata documents and discovery-owned metadata
	 * resources such as `jwks_uri`.
	 *
	 * The transport MUST resolve the hostname exactly once, reject RFC 6890
	 * special-use addresses, pin the approved address for the connection, and
	 * refuse redirects. Those guarantees cannot be implemented by wrapping the
	 * standard Fetch API after DNS resolution, so the application must provide
	 * them at its runtime-specific network boundary.
	 */
	fetchClientMetadataResource: ClientMetadataResourceFetch;
	/**
	 * Apply an additional protocol profile to otherwise generic draft-02
	 * metadata validation.
	 *
	 * The MCP 2026-07-28 profile requires `client_name` and `redirect_uris`
	 * because that MCP revision normatively pins CIMD draft-00.
	 */
	metadataProfile?: CimdMetadataProfile;
	/**
	 * Maximum and fallback cache freshness lifetime for a client's metadata
	 * document. An expired entry is revalidated on the next client resolution;
	 * the plugin does not perform periodic or background fetches.
	 *
	 * Accepts a number of seconds or a duration string (e.g. `"60m"`,
	 * `"1d"`).
	 *
	 * @default "60m"
	 */
	metadataRevalidationInterval?: number | string;
	/**
	 * Bounded request-amplification policy for metadata document fetches.
	 *
	 * A permitted fetch consumes its concurrency and rolling-window budget when
	 * it starts. Same-client concurrent resolutions coalesce, while fresh-cache
	 * hits consume no budget. Limits reject immediately rather than queueing. A
	 * fetch that is still running after 10 seconds stops counting toward the
	 * concurrency limits, so a fetch whose request the runtime ended cannot
	 * hold a slot.
	 */
	metadataFetchPolicy?: CimdMetadataFetchPolicy;
	/**
	 * Maximum number of validated metadata documents retained by the metadata
	 * resolver. The least-recently-used entry is evicted when the bound is
	 * reached.
	 *
	 * @default 1000
	 */
	maxCacheEntries?: number;
	/**
	 * Metadata fields whose URL values must share the same origin as the
	 * `client_id` URL. Prevents a client from claiming URIs on a different
	 * domain.
	 *
	 * Pass an empty array to disable origin binding (not recommended for
	 * production).
	 *
	 * Redirect URIs are deliberately excluded by default: exact redirect URI
	 * matching remains mandatory at authorization time, while native and
	 * distributed clients commonly use a redirect origin different from their
	 * metadata-document origin.
	 *
	 * @default ["post_logout_redirect_uris", "client_uri"]
	 */
	originBoundFields?: readonly string[];
	/**
	 * Pre-fetch gate called before a metadata document is requested. Return
	 * `false` to reject the `client_id` URL.
	 *
	 * Use this for origin allowlists, per-host rate limiting, or integrating
	 * with an external trust service. It is application policy, not a
	 * substitute for the required transport's resolve-once and connection-
	 * pinning guarantees; resolving here would introduce a TOCTOU boundary.
	 *
	 * It runs for each request that needs the document fetched, including
	 * requests that would join another request's in-flight fetch, before any
	 * fetch budget is consumed. Fresh cache hits skip it. Keep it cheap, or cache
	 * its decisions, if it consults an external service.
	 *
	 * @default always allow
	 */
	isMetadataDocumentUrlAllowed?: (
		clientIdUrl: string,
		context: GenericEndpointContext,
	) => boolean | Promise<boolean>;
}

interface CimdClientEventOptions {
	/**
	 * Called after a client is created from a metadata document for the
	 * first time. Use this to assign local trust, emit an audit event, or
	 * perform other post-creation processing. Better Auth does not fetch or
	 * render metadata-owned remote assets such as `logo_uri`.
	 *
	 * This is a best-effort notification. A rejected callback is logged and
	 * does not roll back an otherwise valid registration.
	 */
	onClientCreated?: (event: CimdClientCreatedEvent) => void | Promise<void>;
	/**
	 * Called after a client is refreshed from a re-fetched metadata
	 * document. Use this for change-detection logging or updating derived
	 * fields.
	 *
	 * This is a best-effort notification. A rejected callback is logged and
	 * does not roll back an otherwise valid refresh.
	 */
	onClientRefreshed?: (event: CimdClientRefreshedEvent) => void | Promise<void>;
}

/** Options for a plugin instance that owns its metadata resolver. */
interface CimdOwnedResolverOptions
	extends CimdMetadataResolverOptions,
		CimdClientEventOptions {
	/**
	 * Share one metadata resolver across several plugin instances instead. See
	 * {@link createCimdMetadataResolver}.
	 *
	 * @default a resolver owned by this plugin instance
	 */
	metadataResolver?: undefined;
}

type ResolverOwnedOptions = {
	[Option in keyof CimdMetadataResolverOptions]?: never;
};

/** Options for a plugin instance that uses a shared metadata resolver. */
interface CimdSharedResolverOptions
	extends CimdClientEventOptions,
		ResolverOwnedOptions {
	/**
	 * Share one metadata cache, set of fetch budgets, and in-flight fetch map
	 * across several plugin instances, by passing the result of
	 * {@link createCimdMetadataResolver}. Each request still saves the client
	 * with its own context.
	 *
	 * The resolver owns the transport and every option that governs fetching
	 * and validation, so those options are set on it and cannot be set here.
	 * The plugin fetches discovery-owned resources such as `jwks_uri` with the
	 * resolver's `fetchClientMetadataResource`.
	 */
	metadataResolver: CimdMetadataResolver;
}

/**
 * Options for the Client ID Metadata Document plugin: the fetch and validation
 * options of {@link CimdMetadataResolverOptions}, or a shared
 * `metadataResolver` that carries them.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02
 */
export type CimdOptions = CimdOwnedResolverOptions | CimdSharedResolverOptions;
