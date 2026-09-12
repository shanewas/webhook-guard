# Changelog

## v0.1.1 — 2026-09-12
- Svix secrets that fail to decode fail closed instead of falling back to raw
  bytes. Postgres replay store deletes its own expired row before insert.
- Stripe accepts any valid `v1` (rotation-safe) and tolerates header spacing.
- In-memory replay eviction throttled to once a minute plus same-key check.
- `MapGuardedWebhook` verifier is async (no `.Result` in request path);
  unverified `MapWebhook` marked `[Obsolete]`.
- README quickstart is self-contained and compiles; threat model unchanged.
- 20 tests green.

## v0.1.0 — 2026-09-12
- Verifiers for Stripe (`t=,v1`), GitHub (`sha256=`), Svix (`v1,` multi-sig),
  all with skew windows and constant-time compares.
- `IReplayStore` + in-memory default + `PostgresReplayStore` (ensure table,
  expiry purge) for in-window replay dedupe.
- `MapGuardedWebhook<T>`: verify-before-deserialize minimal-API route with
  typed dispatch; plain `MapWebhook<T>` kept for trusted networks.
- 19 xUnit tests green, including live HTTP route tests.
