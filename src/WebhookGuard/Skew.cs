using System.Text;

namespace WebhookGuard;

public static class Skew
{
    public static bool WithinTolerance(long eventUnixSeconds, long nowUnixSeconds, TimeSpan tolerance)
        => Math.Abs(nowUnixSeconds - eventUnixSeconds) <= (long)tolerance.TotalSeconds;
}
