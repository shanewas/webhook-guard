using System.Text;

namespace WebhookGuard;

public static class StripeVerifier
{
    public static bool Verify(string payload, string header, string secret, long nowUnixSeconds, TimeSpan tolerance)
    {
        if (string.IsNullOrEmpty(payload) || string.IsNullOrEmpty(header) || string.IsNullOrEmpty(secret))
            return false;
        long ts = -1;
        string? v1 = null;
        foreach (var part in header.Split(',', StringSplitOptions.RemoveEmptyEntries))
        {
            var kv = part.Split('=', 2);
            if (kv.Length != 2) continue;
            if (kv[0] == "t" && long.TryParse(kv[1], out var t)) ts = t;
            else if (kv[0] == "v1") v1 = kv[1];
        }
        if (ts < 0 || v1 is null) return false;
        if (!Skew.WithinTolerance(ts, nowUnixSeconds, tolerance)) return false;
        var key = Encoding.UTF8.GetBytes(secret);
        var expected = Crypto.ToHexLower(Crypto.HmacSha256(key, $"{ts}.{payload}"));
        return Crypto.FixedTimeEquals(
            Encoding.ASCII.GetBytes(expected),
            Encoding.ASCII.GetBytes(v1.ToLowerInvariant()));
    }
}
