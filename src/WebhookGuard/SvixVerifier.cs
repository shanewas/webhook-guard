using System.Text;

namespace WebhookGuard;

public static class SvixVerifier
{
    public static bool Verify(string payload, string id, string signatureHeader, string timestamp, string secret, long nowUnixSeconds, TimeSpan tolerance)
    {
        if (string.IsNullOrEmpty(payload) || string.IsNullOrEmpty(id) || string.IsNullOrEmpty(signatureHeader)
            || string.IsNullOrEmpty(timestamp) || string.IsNullOrEmpty(secret))
            return false;
        if (!long.TryParse(timestamp, out var ts)) return false;
        if (!Skew.WithinTolerance(ts, nowUnixSeconds, tolerance)) return false;
        byte[] key;
        var rawSecret = secret.StartsWith("whsec_", StringComparison.Ordinal) ? secret["whsec_".Length..] : secret;
        try { key = Convert.FromBase64String(rawSecret); }
        catch (FormatException) { key = Encoding.UTF8.GetBytes(secret); }
        var expected = Crypto.HmacSha256(key, $"{id}.{timestamp}.{payload}");
        foreach (var part in signatureHeader.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            var sig = part.StartsWith("v1,", StringComparison.Ordinal) ? part[3..] : part;
            byte[] actual;
            try { actual = Convert.FromBase64String(sig); }
            catch (FormatException) { continue; }
            if (actual.Length == expected.Length && Crypto.FixedTimeEquals(actual, expected))
                return true;
        }
        return false;
    }
}
