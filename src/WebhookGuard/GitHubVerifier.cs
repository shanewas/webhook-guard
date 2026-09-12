using System.Text;

namespace WebhookGuard;

public static class GitHubVerifier
{
    private const string Prefix = "sha256=";

    public static bool Verify(byte[] payload, string header, string secret)
    {
        if (payload is null || string.IsNullOrEmpty(header) || string.IsNullOrEmpty(secret))
            return false;
        if (!header.StartsWith(Prefix, StringComparison.Ordinal)) return false;
        var hex = header[Prefix.Length..];
        byte[] actual;
        try { actual = Convert.FromHexString(hex); }
        catch (FormatException) { return false; }
        var expected = Crypto.HmacSha256(Encoding.UTF8.GetBytes(secret), payload);
        return actual.Length == expected.Length && Crypto.FixedTimeEquals(actual, expected);
    }
}
