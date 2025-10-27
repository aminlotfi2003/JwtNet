namespace Application.Identity.RateLimiting;

public enum LoginAttemptOutcome
{
    Success,
    FailedInvalidCredentials,
    RequiresTwoFactor,
    LockedOut
}
