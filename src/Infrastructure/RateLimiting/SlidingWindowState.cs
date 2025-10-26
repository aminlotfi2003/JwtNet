using System.Collections.Concurrent;

namespace Infrastructure.RateLimiting;

internal sealed class SlidingWindowState
{
    private readonly ConcurrentQueue<DateTimeOffset> _events = new();

    public int GetCount(DateTimeOffset now, TimeSpan window)
    {
        Trim(now, window);
        return _events.Count;
    }

    public int Add(DateTimeOffset now, TimeSpan window)
    {
        Trim(now, window);
        _events.Enqueue(now);
        return _events.Count;
    }

    public void Clear() => _events.Clear();

    private void Trim(DateTimeOffset now, TimeSpan window)
    {
        while (_events.TryPeek(out var oldest) && now - oldest >= window)
        {
            _events.TryDequeue(out _);
        }
    }
}

internal sealed class FixedWindowState
{
    private DateTimeOffset _windowStart;
    private int _count;

    public int Count => _count;

    public int Increment(DateTimeOffset now, TimeSpan window)
    {
        EnsureWindow(now, window);
        _count++;
        return _count;
    }

    public int Peek(DateTimeOffset now, TimeSpan window)
    {
        EnsureWindow(now, window);
        return _count;
    }

    public void Reset(DateTimeOffset now)
    {
        _windowStart = now;
        _count = 0;
    }

    private void EnsureWindow(DateTimeOffset now, TimeSpan window)
    {
        if (_windowStart == default)
        {
            _windowStart = now;
            _count = 0;
            return;
        }

        if (now - _windowStart >= window)
        {
            _windowStart = now;
            _count = 0;
        }
    }
}

internal sealed class TokenBucketState
{
    private double _tokens;
    private DateTimeOffset _lastRefill;

    public double Tokens => _tokens;

    public bool TryConsume(DateTimeOffset now, int capacity, TimeSpan refillPeriod)
    {
        Refill(now, capacity, refillPeriod);

        if (_tokens < 1d)
        {
            return false;
        }

        _tokens -= 1d;
        return true;
    }

    private void Refill(DateTimeOffset now, int capacity, TimeSpan refillPeriod)
    {
        if (_lastRefill == default)
        {
            _lastRefill = now;
            _tokens = capacity;
            return;
        }

        var elapsed = now - _lastRefill;
        if (elapsed <= TimeSpan.Zero)
        {
            return;
        }

        var tokensToAdd = elapsed.TotalSeconds / refillPeriod.TotalSeconds * capacity;
        if (tokensToAdd > 0)
        {
            _tokens = Math.Min(capacity, _tokens + tokensToAdd);
            _lastRefill = now;
        }
    }
}

internal sealed class SoftLockState
{
    public DateTimeOffset? LockedUntil { get; private set; }

    public void LockUntil(DateTimeOffset unlockAt)
    {
        LockedUntil = unlockAt;
    }

    public bool IsLocked(DateTimeOffset now)
    {
        if (LockedUntil is null)
        {
            return false;
        }

        if (now >= LockedUntil)
        {
            LockedUntil = null;
            return false;
        }

        return true;
    }
}
