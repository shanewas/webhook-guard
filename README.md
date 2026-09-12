# webhook-guard

Verify webhooks properly: signature, clock skew, replay dedupe, typed routing.
One receiver pipeline for Stripe, GitHub, and Svix senders in ASP.NET Core.

```csharp
app.MapGuardedWebhook<StripeEvent>("payment.succeeded",
    (raw, ctx) => StripeVerifier.Verify(
        payload: Encoding.UTF8.GetString(raw),
        header: ctx.Request.Headers["Stripe-Signature"]!,
        secret: cfg["Stripe:Secret"]!,
        nowUnixSeconds: DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        tolerance: TimeSpan.FromMinutes(5))
        && replay.TryAddAsync(ReplayKeys.For(id, sig), DateTimeOffset.UtcNow.AddMinutes(5)).Result,
    async (evt, ctx) => await orders.MarkPaidAsync(evt.Id));
```

Forged body: rejected. Stale timestamp: rejected. Same delivery twice:
rejected. Only then does your handler run.

## The three checks, and why all three

Most receivers verify the signature and stop. Two holes stay open:

1. **Skew.** A valid signed payload stays valid forever. Without a timestamp
   window, anyone holding an old delivery can re-fire it. Every verifier here
   takes `nowUnixSeconds` + `tolerance` (5 minutes default) and rejects
   anything older. Covered per scheme in `VectorsTests`/`SkewTests`.
2. **Replay inside the window.** A delivery sent twice within 5 minutes passes
   signature + skew both times. `IReplayStore.TryAddAsync` (in-memory default,
   `PostgresReplayStore` optional) drops the second copy. Key it with
   `ReplayKeys.For(messageId, signature)`. Covered by `ReplayTests`.
3. **Unverified routes.** `MapWebhook` without verification is an open door,
   so the guarded route is the one in this README. `MapGuardedWebhook` reads
   the raw body, runs your verifier, and only then deserializes.

All comparisons run in constant time (`CryptographicOperations.FixedTimeEquals`
underneath). Stripe secrets stay raw UTF-8 (even `whsec_` test-mode ones);
Svix `whsec_` secrets get base64-decoded per their spec.

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

## Postgres replay store

`PostgresReplayStore.EnsureTableAsync` creates `webhook_guard_replay`.
Call `PurgeExpiredAsync` on a timer; the table doesn't clean itself.

## Tests

19 xUnit tests: known vectors per scheme, skew rejects, tamper rejects,
replay rejects, live route tests for guarded and unguarded mapping.

## License

MIT.
