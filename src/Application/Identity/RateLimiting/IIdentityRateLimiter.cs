namespace Application.Identity.RateLimiting;

public interface IIdentityRateLimiter
{
    Task<RateLimitOutcome> EnforceRegisterAsync(RegisterRateLimitContext context, CancellationToken cancellationToken);
    Task<RateLimitOutcome> CheckLoginAsync(LoginRateLimitContext context, CancellationToken cancellationToken);
    Task<RateLimitOutcome> RegisterLoginResultAsync(LoginRateLimitContext context, LoginAttemptOutcome outcome, CancellationToken cancellationToken);
    Task<RateLimitOutcome> RegisterTwoFactorAttemptAsync(TwoFactorRateLimitContext context, bool succeeded, CancellationToken cancellationToken);
    Task<RateLimitOutcome> RegisterRefreshAttemptAsync(RefreshRateLimitContext context, bool success, CancellationToken cancellationToken);
    Task<RateLimitOutcome> RegisterLogoutAttemptAsync(SimpleRateLimitContext context, CancellationToken cancellationToken);
    Task<RateLimitOutcome> RegisterPasswordRotateAttemptAsync(PasswordRotateRateLimitContext context, PasswordRotateAttemptType attemptType, bool succeeded, CancellationToken cancellationToken);
    Task<RateLimitOutcome> RegisterForgotPasswordSendAsync(ForgotPasswordRateLimitContext context, CancellationToken cancellationToken);
    Task<RateLimitOutcome> RegisterForgotPasswordVerifyAsync(VerifyResetRateLimitContext context, bool succeeded, CancellationToken cancellationToken);
    Task<RateLimitOutcome> RegisterResetPasswordAsync(ResetPasswordRateLimitContext context, bool succeeded, CancellationToken cancellationToken);
    Task<RateLimitOutcome> RegisterTwoFactorEmailGenerateAsync(TwoFactorEmailRateLimitContext context, CancellationToken cancellationToken);
    Task<RateLimitOutcome> RegisterTwoFactorEmailEnableAsync(TwoFactorEmailRateLimitContext context, bool succeeded, CancellationToken cancellationToken);
}

public sealed record RegisterRateLimitContext(string? IpAddress, string? Asn, string? EmailDomain, string? TenantId, bool IsDisposableDomain);

public sealed record LoginRateLimitContext(string NormalizedEmail, string? IpAddress, string? DeviceId, string? TenantId, bool IsHighRisk);

public sealed record TwoFactorRateLimitContext(string ChallengeKey, string AccountKey, string? IpAddress);

public sealed record RefreshRateLimitContext(string SessionKey, string AccountKey, string? ClientId, string? IpAddress);

public sealed record SimpleRateLimitContext(string? AccountKey, string? IpAddress);

public enum PasswordRotateAttemptType
{
    VerifyCurrentPassword,
    Rotate
}

public sealed record PasswordRotateRateLimitContext(string AccountKey, string? IpAddress);

public sealed record ForgotPasswordRateLimitContext(string AccountKey, string? IpAddress, string? TenantId);

public sealed record VerifyResetRateLimitContext(string FlowKey, string? IpAddress);

public sealed record ResetPasswordRateLimitContext(string AccountKey, string TokenKey, string? IpAddress);

public sealed record TwoFactorEmailRateLimitContext(string AccountKey, string? IpAddress);
