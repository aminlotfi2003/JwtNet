using Domain.Entities;

namespace Application.Abstractions.Services;

public interface IPasswordResetCodeNotificationService
{
    Task NotifyAsync(
        ApplicationUser user,
        string resetToken,
        string verificationCode,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default);
}
