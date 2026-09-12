using System.Text;

namespace WebhookGuard;

public static class StripeVerifier
{
    public static bool Verify(string payload, string header, string secret, long nowUnixSeconds, TimeSpan tolerance)
    {
        if (string.IsNullOrEmpty(payload) || string.IsNullOrEmpty(header) || string.IsNullOrEmpty(secret))
            return false;
        long ts = -1;
        var v1s = new List<string>();
        foreach (var part in header.Split(',', StringSplitOptions.RemoveEmptyEntries))
        {
            var kv = part.Trim().Split('=', 2);
            if (kv.Length != 2) continue;
            if (kv[0] == "t" && long.TryParse(kv[1].Trim(), out var t)) ts = t;
            else if (kv[0] == "v1") v1s.Add(kv[1].Trim());
        }
        if (ts < 0 || v1s.Count == 0) return false;
        if (!Skew.WithinTolerance(ts, nowUnixSeconds, tolerance)) return false;
        var key = Encoding.UTF8.GetBytes(secret);
        var expected = Encoding.ASCII.GetBytes(Crypto.ToHexLower(Crypto.HmacSha256(key, $"{ts}.{payload}")));
        return v1s.Any(v =>
        {
            var actual = Encoding.ASCII.GetBytes(v.ToLowerInvariant());
            return actual.Length == expected.Length && Crypto.FixedTimeEquals(actual, expected);
        });
    }
}
