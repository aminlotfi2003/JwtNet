namespace Application.Identity.RateLimiting;

public sealed record RateLimitOutcome(
    bool IsAllowed,
    IdentityRateLimitAction Action,
    TimeSpan? Delay = null,
    TimeSpan? RetryAfter = null,
    TimeSpan? LockDuration = null)
{
    public static RateLimitOutcome Allowed(TimeSpan? delay = null) =>
        new(true, delay.HasValue ? IdentityRateLimitAction.Delay : IdentityRateLimitAction.None, delay);

    public static RateLimitOutcome Blocked(IdentityRateLimitAction action, TimeSpan? retryAfter = null, TimeSpan? lockDuration = null) =>
        new(false, action, null, retryAfter, lockDuration);
}
