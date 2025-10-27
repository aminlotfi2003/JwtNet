namespace Application.Identity.RateLimiting;

public enum IdentityRateLimitAction
{
    None = 0,
    Delay,
    RequireCaptcha,
    StepUpMfa,
    SoftLock,
    Block,
    RevokeToken,
    RegenerateChallenge
}
