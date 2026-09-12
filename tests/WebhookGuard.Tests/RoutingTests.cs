using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using WebhookGuard;

namespace WebhookGuard.Tests;

public sealed record TestEvent(string EventType, string Id);

public class RoutingTests
{
    [Fact]
    public void TryMatch_SameType_True()
        => Assert.True(WebhookRouting.TryMatch(new TestEvent("user.created", "1"), "user.created"));

    [Fact]
    public void TryMatch_OtherType_False()
        => Assert.False(WebhookRouting.TryMatch(new TestEvent("user.created", "1"), "user.deleted"));

    [Fact]
    public async Task MapWebhook_DispatchesMatchingEvent()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        var app = builder.Build();
        var got = new List<string>();
        app.MapWebhook<TestEvent>("user.created", (evt, _) => { got.Add(evt.Id); return Task.CompletedTask; });
        await app.StartAsync();
        try
        {
            var baseUrl = app.Urls.First();
            using var client = new HttpClient();
            var ok = await client.PostAsJsonAsync($"{baseUrl}/webhooks/user.created",
                new TestEvent("user.created", "evt-1"));
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
            Assert.Equal(["evt-1"], got);
            var miss = await client.PostAsJsonAsync($"{baseUrl}/webhooks/user.created",
                new TestEvent("user.deleted", "evt-2"));
            Assert.Equal(HttpStatusCode.NotFound, miss.StatusCode);
        }
        finally { await app.StopAsync(); }
    }

    [Fact]
    public async Task MapGuardedWebhook_RejectsBadSignature()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        var app = builder.Build();
        var got = new List<string>();
        static bool verify(byte[] raw, Microsoft.AspNetCore.Http.HttpContext ctx)
            => ctx.Request.Headers.TryGetValue("X-Sig", out var v) && v == "good";
        app.MapGuardedWebhook<TestEvent>("user.created", verify, (evt, _) => { got.Add(evt.Id); return Task.CompletedTask; });
        await app.StartAsync();
        try
        {
            var baseUrl = app.Urls.First();
            using var client = new HttpClient();
            var bad = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/webhooks/user.created")
            {
                Content = JsonContent.Create(new TestEvent("user.created", "evt-9"))
            };
            bad.Headers.Add("X-Sig", "forged");
            Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(bad)).StatusCode);
            Assert.Empty(got);
            var good = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/webhooks/user.created")
            {
                Content = JsonContent.Create(new TestEvent("user.created", "evt-9"))
            };
            good.Headers.Add("X-Sig", "good");
            Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(good)).StatusCode);
            Assert.Equal(["evt-9"], got);
        }
        finally { await app.StopAsync(); }
    }
}
