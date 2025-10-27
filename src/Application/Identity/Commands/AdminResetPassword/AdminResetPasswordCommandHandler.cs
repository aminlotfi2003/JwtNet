using Application.Abstractions.Repositories;
using Application.Abstractions.Services;
using Application.Common.Exceptions;
using Application.Identity.DTOs;
using Application.Identity.RateLimiting;
using Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace Application.Identity.Commands.AdminResetPassword;

internal sealed class AdminResetPasswordCommandHandler
    : IRequestHandler<AdminResetPasswordCommand, ApplicationUserDto>
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IRefreshTokenRepository _refreshTokens;
    private readonly IUserPasswordHistoryRepository _passwordHistories;
    private readonly IDateTimeProvider _clock;

    public AdminResetPasswordCommandHandler(
        UserManager<ApplicationUser> userManager,
        IRefreshTokenRepository refreshTokens,
        IUserPasswordHistoryRepository passwordHistories,
        IDateTimeProvider clock)
    {
        _userManager = userManager;
        _refreshTokens = refreshTokens;
        _passwordHistories = passwordHistories;
        _clock = clock;
    }

    public async Task<ApplicationUserDto> Handle(AdminResetPasswordCommand request, CancellationToken cancellationToken)
    {
        var user = await _userManager.FindByIdAsync(request.UserId.ToString());
        if (user is null)
            throw new NotFoundException(IdentityRateLimitMessages.GenericError);

        var recentPasswords = await _passwordHistories.GetRecentAsync(user.Id, 5, cancellationToken);

        foreach (var previous in recentPasswords)
        {
            var verification = _userManager.PasswordHasher.VerifyHashedPassword(user, previous.PasswordHash, request.NewPassword);
            if (verification is PasswordVerificationResult.Success or PasswordVerificationResult.SuccessRehashNeeded)
                throw new BadRequestException(IdentityRateLimitMessages.GenericError);
        }

        if (!string.IsNullOrEmpty(user.PasswordHash))
        {
            var currentVerification = _userManager.PasswordHasher.VerifyHashedPassword(user, user.PasswordHash, request.NewPassword);
            if (currentVerification is PasswordVerificationResult.Success or PasswordVerificationResult.SuccessRehashNeeded)
                throw new BadRequestException(IdentityRateLimitMessages.GenericError);
        }

        var previousPasswordHash = user.PasswordHash;

        var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
        var result = await _userManager.ResetPasswordAsync(user, resetToken, request.NewPassword);
        if (!result.Succeeded)
        {
            var description = string.Join("; ", result.Errors.Select(e => e.Description));
            _ = description;
            throw new BadRequestException(IdentityRateLimitMessages.GenericError);
        }

        user.LastPasswordChangedAt = _clock.UtcNow;
        await _userManager.UpdateAsync(user);

        if (!string.IsNullOrEmpty(previousPasswordHash))
        {
            var historyEntry = UserPasswordHistory.Create(user.Id, previousPasswordHash!, _clock.UtcNow);
            await _passwordHistories.AddAsync(historyEntry, cancellationToken);
            await _passwordHistories.PruneExcessAsync(user.Id, 5, cancellationToken);
            await _passwordHistories.SaveChangesAsync(cancellationToken);
        }

        await _refreshTokens.RevokeUserTokensAsync(user.Id, cancellationToken);
        await _refreshTokens.SaveChangesAsync(cancellationToken);

        return ApplicationUserDto.FromEntity(user);
    }
}
