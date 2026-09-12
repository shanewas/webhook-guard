using System.Text;
using WebhookGuard;

namespace WebhookGuard.Tests;

public class VectorsTests
{
    private static readonly TimeSpan Tol = TimeSpan.FromMinutes(5);
    private const long Now = 1700000000;

    [Fact]
    public void Stripe_KnownVector_Accepts()
    {
        var payload = "{\"id\":\"evt_1\"}";
        var header = "t=1700000000,v1=cf6ab59db2a13f14509ca6aa99ba5ef44464e3a9324845094c4c6205f0c1773e";
        Assert.True(StripeVerifier.Verify(payload, header, "whsec_test_stripe", Now, Tol));
    }

    [Fact]
    public void Stripe_TamperedPayload_Rejects()
    {
        var header = "t=1700000000,v1=cf6ab59db2a13f14509ca6aa99ba5ef44464e3a9324845094c4c6205f0c1773e";
        Assert.False(StripeVerifier.Verify("{\"id\":\"evt_2\"}", header, "whsec_test_stripe", Now, Tol));
    }

    [Fact]
    public void GitHub_KnownVector_Accepts()
    {
        var payload = Encoding.UTF8.GetBytes("{\"action\":\"opened\"}");
        Assert.True(GitHubVerifier.Verify(payload,
            "sha256=30cccbdb5497960247c4adf838464b48119a952d8cd3c83f666907b65ce37208",
            "github_test_secret"));
    }

    [Fact]
    public void GitHub_Tampered_Rejects()
    {
        var payload = Encoding.UTF8.GetBytes("{\"action\":\"closed\"}");
        Assert.False(GitHubVerifier.Verify(payload,
            "sha256=30cccbdb5497960247c4adf838464b48119a952d8cd3c83f666907b65ce37208",
            "github_test_secret"));
    }

    [Fact]
    public void Svix_KnownVector_Accepts()
    {
        const string sec = "c3ZpeF90ZXN0X3NlY3JldF8zMmJ5dGVzX3h4eHh4eA==";
        Assert.True(SvixVerifier.Verify("{\"type\":\"user.created\"}", "msg_1",
            "v1,8j5GrURYwgGvknYe0CFhd00OVYdBq4G8H2Z4nVXoBxk=", "1700000000", sec, Now, Tol));
    }

    [Fact]
    public void Svix_MultiSignature_AcceptsSecondValid()
    {
        const string sec = "c3ZpeF90ZXN0X3NlY3JldF8zMmJ5dGVzX3h4eHh4eA==";
        Assert.True(SvixVerifier.Verify("{\"type\":\"user.created\"}", "msg_1",
            "v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= v1,8j5GrURYwgGvknYe0CFhd00OVYdBq4G8H2Z4nVXoBxk=",
            "1700000000", sec, Now, Tol));
    }

    [Fact]
    public void Svix_Tampered_Rejects()
    {
        const string sec = "c3ZpeF90ZXN0X3NlY3JldF8zMmJ5dGVzX3h4eHh4eA==";
        Assert.False(SvixVerifier.Verify("{\"type\":\"user.deleted\"}", "msg_1",
            "v1,8j5GrURYwgGvknYe0CFhd00OVYdBq4G8H2Z4nVXoBxk=", "1700000000", sec, Now, Tol));
    }
}
