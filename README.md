# webhook-guard

For SaaS backends receiving Stripe, GitHub, or Svix webhooks: verify
signatures, reject stale and replayed deliveries, route typed events.
One receiver pipeline in ASP.NET Core.

```csharp
using System.Text;
using WebhookGuard;

var replay = new InMemoryReplayStore();
var secret = builder.Configuration["Stripe:Secret"]!;
var tolerance = TimeSpan.FromMinutes(5);

app.MapGuardedWebhook<StripeEvent>("payment.succeeded",
    async (raw, ctx) =>
    {
        var payload = Encoding.UTF8.GetString(raw);
        var header = ctx.Request.Headers["Stripe-Signature"].ToString();
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (!StripeVerifier.Verify(payload, header, secret, now, tolerance))
            return false;
        var evt = System.Text.Json.JsonSerializer.Deserialize<StripeEvent>(raw)!;
        var ok = await replay.TryAddAsync(
            ReplayKeys.For(evt.Id, header), DateTimeOffset.UtcNow + tolerance);
        return ok;
    },
    async (evt, _) => await orders.MarkPaidAsync(evt.Id));

public sealed record StripeEvent(string Id, string Type);
```

Install: `dotnet add package WebhookGuard.AspNetCore`. Forged body: 401. Stale
timestamp: 401. Same delivery twice: 401. Only then does your handler run.

Replay keys need a stable message id plus the signature. Stripe: the event
`id` from the payload. GitHub: the `X-GitHub-Delivery` header. Svix: the
`svix-id` header. `ReplayKeys.For(id, signature)` combines them.

## The three checks, and why all three

Most receivers verify the signature and stop. Two holes stay open:

1. **Skew.** A valid signed payload stays valid forever. Without a timestamp
   window, anyone holding an old delivery can re-fire it. Every verifier here
   takes the current time plus a tolerance (5 minutes default) and rejects
   anything older. Covered per scheme in `VectorsTests` and `SkewTests`.
2. **Replay inside the window.** A delivery sent twice within 5 minutes passes
   signature plus skew both times. `IReplayStore.TryAddAsync` (in-memory
   default, `PostgresReplayStore` optional) drops the second copy. Covered by
   `ReplayTests`.
3. **Unverified routes.** The plain `MapWebhook` mapper is marked `[Obsolete]`
   because it routes without checking anything. `MapGuardedWebhook` reads the
   raw body, runs your async verifier, and only then deserializes.

All comparisons run in constant time. Stripe secrets stay raw UTF-8 (even
`whsec_` test-mode ones, exactly as Stripe sends them). Svix `whsec_` secrets
get base64-decoded per their spec, and anything that fails to decode fails
closed. Stripe accepts any valid `v1` signature, so key rotation never breaks
verification. Covered by `Stripe_RotationSecondV1_Accepts`.

## Postgres replay store

```csharp
await PostgresReplayStore.EnsureTableAsync(connString);
// per request:
var pg = new PostgresReplayStore(connString);
```

Call `PostgresReplayStore.PurgeExpiredAsync(connString)` on a timer. The
table doesn't clean itself.

## Threat model, plainly

Stops: forged payloads, stale replays, duplicate deliveries, wrong-type
dispatch. Doesn't stop: a leaked signing secret (rotate it), a compromised
sender, or your handler's own bugs. Hash comparisons don't make a bad secret
good.

## Not Svix, not verihook

Svix is hosted delivery infrastructure. This is the receiver side Svix users
still hand-roll. `verihook` and `webhook-verify` check signatures; guard adds
skew windows, replay stores, and the guarded route tying it together. If you
only need "is this signature valid", those smaller packages fit. If you need
the full receiver, this one does.

## Tests

20 xUnit tests: known vectors per scheme, skew rejects, tamper rejects,
replay rejects, rotation acceptance, live HTTP route tests.

Part of a trilogy: webhook-guard (verify at ingress) → idempotency-keys
(dedupe) → pg-outbox (publish at egress).

## License

MIT.
