---
"@better-auth/cimd": patch
---

A Client ID Metadata Document fetch that never settles, as when a runtime ends the request that started it, now stops counting toward `maximumConcurrentFetches` and `maximumConcurrentFetchesPerOrigin` 10 seconds after it started. Before, it held its slot until the process restarted, so requests for other clients could fail with `temporarily_unavailable`.
