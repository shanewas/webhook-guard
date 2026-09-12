using WebhookGuard;

namespace WebhookGuard.Tests;

public class ReplayTests
{
    [Fact]
    public async Task SecondDeliverySameKey_Rejects()
    {
        var store = new InMemoryReplayStore();
        var key = ReplayKeys.For("msg_1", "sig_abc");
        var exp = DateTimeOffset.UtcNow.AddHours(24);
        Assert.True(await store.TryAddAsync(key, exp));
        Assert.False(await store.TryAddAsync(key, exp));
    }

    [Fact]
    public async Task DifferentSignature_Accepts()
    {
        var store = new InMemoryReplayStore();
        var exp = DateTimeOffset.UtcNow.AddHours(24);
        Assert.True(await store.TryAddAsync(ReplayKeys.For("msg_1", "sig_a"), exp));
        Assert.True(await store.TryAddAsync(ReplayKeys.For("msg_1", "sig_b"), exp));
    }

    [Fact]
    public async Task ExpiredKey_AllowsReadd()
    {
        var store = new InMemoryReplayStore();
        var key = ReplayKeys.For("msg_x", "sig_x");
        Assert.True(await store.TryAddAsync(key, DateTimeOffset.UtcNow.AddMilliseconds(-1)));
        Assert.True(await store.TryAddAsync(key, DateTimeOffset.UtcNow.AddHours(1)));
    }
}
