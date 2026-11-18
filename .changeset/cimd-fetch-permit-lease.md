---
"@better-auth/cimd": patch
---

A Client ID Metadata Document fetch that never settles, as when a runtime ends the request that started it, now stops counting toward `maximumConcurrentFetches` and `maximumConcurrentFetchesPerOrigin` 10 seconds after it started. Before, it held its slot until the process restarted, so requests for other clients could fail with `temporarily_unavailable`. When such a fetch answers after its slot was taken back and no newer fetch or cached document replaced it, its document is now used instead of being fetched again, and a retired fetch's failure no longer reaches the requests that waited for it.
