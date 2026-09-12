using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace WebhookGuard;

public delegate Task WebhookHandler<T>(T evt, HttpContext ctx);

public static class WebhookRouting
{
    [Obsolete("Unverified route: anyone can POST forged events. Use MapGuardedWebhook with a verifier instead.")]
    public static RouteHandlerBuilder MapWebhook<T>(this IEndpointRouteBuilder app, string eventType, WebhookHandler<T> handler)
        => app.MapPost($"/webhooks/{eventType}", async (HttpContext ctx) =>
        {
            var evt = await JsonSerializer.DeserializeAsync<T>(ctx.Request.Body,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (evt is null) return Results.BadRequest();
            if (!TryMatch(evt, eventType)) return Results.NotFound();
            await handler(evt, ctx);
            return Results.Ok();
        });

    public delegate Task<bool> RawVerifier(byte[] rawBody, HttpContext ctx);

    public static RouteHandlerBuilder MapGuardedWebhook<T>(this IEndpointRouteBuilder app, string eventType, RawVerifier verify, WebhookHandler<T> handler)
        => app.MapPost($"/webhooks/{eventType}", async (HttpContext ctx) =>
        {
            using var ms = new MemoryStream();
            await ctx.Request.Body.CopyToAsync(ms);
            var raw = ms.ToArray();
            if (!await verify(raw, ctx)) return Results.Unauthorized();
            var evt = JsonSerializer.Deserialize<T>(raw,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (evt is null) return Results.BadRequest();
            if (!TryMatch(evt, eventType)) return Results.NotFound();
            await handler(evt, ctx);
            return Results.Ok();
        });

    public static bool TryMatch<T>(T evt, string eventType)
    {
        if (evt is IDictionary<string, object?> d)
            return d.TryGetValue("eventType", out var v) && v?.ToString() == eventType;
        var p = evt?.GetType().GetProperty("EventType") ?? evt?.GetType().GetProperty("Type");
        return p?.GetValue(evt)?.ToString() == eventType;
    }
}
