using System.Net;
using Application.Identity.RateLimiting;

namespace Application.Common.Exceptions;

public sealed class RateLimitException : HttpException
{
    public RateLimitException(IdentityRateLimitAction action, TimeSpan? retryAfter = null, TimeSpan? lockDuration = null)
        : base(HttpStatusCode.TooManyRequests, IdentityRateLimitMessages.GenericError)
    {
        Action = action;
        RetryAfter = retryAfter;
        LockDuration = lockDuration;
    }

    public IdentityRateLimitAction Action { get; }

    public TimeSpan? RetryAfter { get; }

    public TimeSpan? LockDuration { get; }
}
