using System.Security.Cryptography;
using System.Text;

namespace WebhookGuard;

public sealed class WebhookGuardOptions
{
    public TimeSpan TimestampTolerance { get; set; } = TimeSpan.FromMinutes(5);
    public TimeSpan ReplayWindow { get; set; } = TimeSpan.FromHours(24);
}

public static class Crypto
{
    public static byte[] HmacSha256(byte[] key, string data)
        => HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(data));

    public static byte[] HmacSha256(byte[] key, byte[] data)
        => HMACSHA256.HashData(key, data);

    public static bool FixedTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        => CryptographicOperations.FixedTimeEquals(a, b);

    public static string ToHexLower(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();
}
