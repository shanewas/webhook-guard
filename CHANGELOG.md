# Changelog

## v0.1.0 — 2026-09-12
- Verifiers for Stripe (`t=,v1`), GitHub (`sha256=`), Svix (`v1,` multi-sig),
  all with skew windows and constant-time compares.
- `IReplayStore` + in-memory default + `PostgresReplayStore` (ensure table,
  expiry purge) for in-window replay dedupe.
- `MapGuardedWebhook<T>`: verify-before-deserialize minimal-API route with
  typed dispatch; plain `MapWebhook<T>` kept for trusted networks.
- 19 xUnit tests green, including live HTTP route tests.
