# webhook-guard — Specification

## 1. Problem & buyer
Every Stripe/GitHub/Svix receiver hand-rolls signature verify, clock-skew
checks, and replay protection — usually wrong (no skew window, no dedup store).
Buyer: any SaaS backend dev. Self-hosted receiver side Svix users still hand-roll.

## 2. Differentiation (verified 2026-09-12, constraint applied)
- Svix is hosted SaaS delivery — NOT a competitor; guard is the embeddable
  receiver side. Embeddable rivals exist: `verihook` (typed, 12+ providers),
  `hookproof`, `webhook-verify`, Svix SDKs. README MUST position vs verihook
  explicitly.
- Beat angle: verify + timestamp-skew + Postgres replay-dedupe log + typed
  handler routing in one receiver pipeline (rivals stop at verify). No hosting,
  no delivery infra — never a Svix clone.

## 3. Stack
.NET 9 (+ TS verifier port if trivial), Postgres optional (replay log). MIT.

## 4. v0.1 scope (<= ~1.5k LOC)
- Schemes: Stripe (t=,v1 HMAC), GitHub (sha256=), Svix (svix-id/signature/timestamp).
- Skew check (configurable tolerance, default 5 min), constant-time compare.
- Replay dedupe: message-id + signature store (in-memory default, Postgres
  optional), configurable window.
- Typed routing: `MapWebhook<T>(eventType, handler)` minimal-API extension.
- Tests: xUnit — known-vector signatures per scheme, skew reject, replay
  reject, tamper reject, routing test.
- Non-goals: no delivery infra, no hosted relay, no dashboard, no new schemes
  beyond the three.

## 5. Architecture (file tree)
- src/WebhookGuard/{Schemes/Stripe, Schemes/GitHub, Schemes/Svix, Skew,
  ReplayStore, Routing}.cs (+ .Postgres store)
- tests/WebhookGuard.Tests/{Vectors,Skew,Replay,Routing}Tests.cs
- README.md, CHANGELOG.md, LICENSE (MIT)

## 6. Anti-patterns
- No "military-grade" language. Threat model stated: protects against
  forgery/replay, NOT against sender compromise or leaked secrets.
- No timing-attack-vulnerable compares. No invented provider support.

## 7. Release criteria
- `dotnet test` green incl. known-vector tests. README 5-min quickstart +
  threat-model section + verihook/Svix positioning. CHANGELOG. Tag v0.1.0.
  nupkg in dist/.

## Portfolio coherence
Request lifecycle trilogy: webhook-guard (ingress) -> idempotency-keys (dedupe)
-> pg-outbox (egress). Shared buyer, cross-linked READMEs.
