using Application.Abstractions.Services;
using Domain.Entities;
using Microsoft.Extensions.Logging;

namespace Infrastructure.Services;

public sealed class LoggingPasswordResetCodeNotificationService(
    ILogger<LoggingPasswordResetCodeNotificationService> logger)
    : IPasswordResetCodeNotificationService
{
    private readonly ILogger<LoggingPasswordResetCodeNotificationService> _logger = logger;

    public Task NotifyAsync(
        ApplicationUser user,
        string resetToken,
        string verificationCode,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation(
            "Password reset requested for {Email}. Verification code: {VerificationCode} (expires at {ExpiresAt:u}). Reset token: {ResetToken}",
            user.Email,
            verificationCode,
            expiresAt,
            resetToken);

        return Task.CompletedTask;
    }
}
