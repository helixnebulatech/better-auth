---
"@better-auth/cimd": minor
---

`createCimdMetadataResolver` lets a runtime that builds its auth instance for each request share one metadata cache, one set of fetch limits, and in-flight fetches between those instances. Create the resolver once and pass it to `cimd()` as `metadataResolver`; each request still saves the client with its own context, and no request waits for another request's save or for a shared fetch that never settles for more than 10 seconds. The options that govern fetching and validation, such as `metadataProfile`, `originBoundFields`, and `isMetadataDocumentUrlAllowed`, belong to the resolver and are rejected next to `metadataResolver`.
