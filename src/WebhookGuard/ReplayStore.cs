using System.Collections.Concurrent;
using Npgsql;

namespace WebhookGuard;

public interface IReplayStore
{
    Task<bool> TryAddAsync(string key, DateTimeOffset expiresAt, CancellationToken ct = default);
}

public sealed class InMemoryReplayStore : IReplayStore
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _seen = new();

    private long _lastEvictTicks;

    public Task<bool> TryAddAsync(string key, DateTimeOffset expiresAt, CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow;
        if (now.Ticks - Interlocked.Read(ref _lastEvictTicks) > TimeSpan.FromMinutes(1).Ticks)
        {
            Interlocked.Exchange(ref _lastEvictTicks, now.Ticks);
            EvictExpired(now);
        }
        else if (_seen.TryGetValue(key, out var exp) && exp <= now)
        {
            _seen.TryRemove(key, out _);
        }
        return Task.FromResult(_seen.TryAdd(key, expiresAt));
    }

    private void EvictExpired(DateTimeOffset now)
    {
        foreach (var kv in _seen)
            if (kv.Value <= now)
                _seen.TryRemove(kv.Key, out _);
    }
}

public sealed class PostgresReplayStore(string connectionString) : IReplayStore
{
    public async Task<bool> TryAddAsync(string key, DateTimeOffset expiresAt, CancellationToken ct = default)
    {
        await using var conn = new NpgsqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await using (var del = new NpgsqlCommand(
            "delete from webhook_guard_replay where key = $1 and expires_at < now()", conn))
        {
            del.Parameters.AddWithValue(key);
            await del.ExecuteNonQueryAsync(ct);
        }
        await using var cmd = new NpgsqlCommand(
            "insert into webhook_guard_replay(key, expires_at) values ($1, $2) on conflict (key) do nothing",
            conn);
        cmd.Parameters.AddWithValue(key);
        cmd.Parameters.AddWithValue(expiresAt.UtcDateTime);
        return await cmd.ExecuteNonQueryAsync(ct) == 1;
    }

    public static async Task PurgeExpiredAsync(string connectionString, CancellationToken ct = default)
    {
        await using var conn = new NpgsqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await using var cmd = new NpgsqlCommand("delete from webhook_guard_replay where expires_at < now()", conn);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public static async Task EnsureTableAsync(string connectionString, CancellationToken ct = default)
    {
        await using var conn = new NpgsqlConnection(connectionString);
        await conn.OpenAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "create table if not exists webhook_guard_replay(key text primary key, expires_at timestamptz not null)",
            conn);
        await cmd.ExecuteNonQueryAsync(ct);
    }
}

public static class ReplayKeys
{
    public static string For(string messageId, string signature) => $"{messageId}.{signature}";
}
