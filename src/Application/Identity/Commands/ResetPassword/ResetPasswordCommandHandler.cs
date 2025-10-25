using Application.Abstractions.Repositories;
using Application.Abstractions.Services;
using Application.Identity.DTOs;
using Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace Application.Identity.Commands.ResetPassword;

internal sealed class ResetPasswordCommandHandler : IRequestHandler<ResetPasswordCommand, PasswordResetResultDto>
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IPasswordResetCodeRepository _resetCodes;
    private readonly IUserPasswordHistoryRepository _passwordHistories;
    private readonly IRefreshTokenRepository _refreshTokens;
    private readonly IDateTimeProvider _clock;

    public ResetPasswordCommandHandler(
        UserManager<ApplicationUser> userManager,
        IPasswordResetCodeRepository resetCodes,
        IUserPasswordHistoryRepository passwordHistories,
        IRefreshTokenRepository refreshTokens,
        IDateTimeProvider clock)
    {
        _userManager = userManager;
        _resetCodes = resetCodes;
        _passwordHistories = passwordHistories;
        _refreshTokens = refreshTokens;
        _clock = clock;
    }

    public async Task<PasswordResetResultDto> Handle(ResetPasswordCommand request, CancellationToken cancellationToken)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user is null)
            return PasswordResetResultDto.SuccessResult("If an account with that email exists, its password has been updated.");

        var resetCode = await _resetCodes.GetLatestForUserAsync(user.Id, cancellationToken);
        if (resetCode is null)
            return PasswordResetResultDto.FailureResult("Invalid verification code.");

        if (resetCode.IsExpired(_clock.UtcNow))
            return PasswordResetResultDto.FailureResult("The verification code has expired. Please request a new one.");

        var verification = _userManager.PasswordHasher.VerifyHashedPassword(
            user,
            resetCode.CodeHash,
            request.VerificationCode);

        if (verification is not PasswordVerificationResult.Success and not PasswordVerificationResult.SuccessRehashNeeded)
            return PasswordResetResultDto.FailureResult("Invalid verification code.");

        var recentPasswords = await _passwordHistories.GetRecentAsync(user.Id, 5, cancellationToken);

        foreach (var previous in recentPasswords)
        {
            var previousVerification = _userManager.PasswordHasher.VerifyHashedPassword(user, previous.PasswordHash, request.NewPassword);
            if (previousVerification is PasswordVerificationResult.Success or PasswordVerificationResult.SuccessRehashNeeded)
                return PasswordResetResultDto.FailureResult("New password cannot match any of the last five passwords.");
        }

        if (!string.IsNullOrEmpty(user.PasswordHash))
        {
            var currentVerification = _userManager.PasswordHasher.VerifyHashedPassword(user, user.PasswordHash, request.NewPassword);
            if (currentVerification is PasswordVerificationResult.Success or PasswordVerificationResult.SuccessRehashNeeded)
                return PasswordResetResultDto.FailureResult("New password cannot match the current password.");
        }

        var previousPasswordHash = user.PasswordHash;

        var result = await _userManager.ResetPasswordAsync(user, request.ResetToken, request.NewPassword);
        if (!result.Succeeded)
        {
            var description = string.Join("; ", result.Errors.Select(error => error.Description));
            return PasswordResetResultDto.FailureResult($"Unable to reset password: {description}");
        }

        resetCode.MarkVerified(_clock.UtcNow);
        await _resetCodes.RemoveAllForUserAsync(user.Id, cancellationToken);
        await _resetCodes.SaveChangesAsync(cancellationToken);

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

        return PasswordResetResultDto.SuccessResult("Password reset successfully.");
    }
}
