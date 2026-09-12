using WebhookGuard;

namespace WebhookGuard.Tests;

public class SkewTests
{
    private static readonly TimeSpan Tol = TimeSpan.FromMinutes(5);

    [Fact]
    public void Stripe_StaleTimestamp_Rejects()
    {
        var payload = "{\"id\":\"evt_1\"}";
        var header = "t=1699999000,v1=anything";
        Assert.False(StripeVerifier.Verify(payload, header, "whsec_test_stripe", 1700000000, Tol));
    }

    [Fact]
    public void Stripe_FutureTimestamp_Rejects()
    {
        var header = "t=1700001000,v1=anything";
        Assert.False(StripeVerifier.Verify("{}", header, "s", 1700000000, Tol));
    }

    [Fact]
    public void Skew_Boundary_Accepts()
        => Assert.True(Skew.WithinTolerance(1700000000 - 300, 1700000000, Tol));

    [Fact]
    public void Skew_JustOutside_Rejects()
        => Assert.False(Skew.WithinTolerance(1700000000 - 301, 1700000000, Tol));

    [Fact]
    public void Skew_CustomTolerance_Respected()
        => Assert.True(Skew.WithinTolerance(1700000000 - 600, 1700000000, TimeSpan.FromMinutes(15)));
}
