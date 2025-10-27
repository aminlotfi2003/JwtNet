using Application.Abstractions.Repositories;
using Application.Abstractions.Services;
using Application.Common.Exceptions;
using Application.Identity.DTOs;
using Application.Identity.RateLimiting;
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
    private readonly IIdentityRateLimiter _rateLimiter;

    public ResetPasswordCommandHandler(
        UserManager<ApplicationUser> userManager,
        IPasswordResetCodeRepository resetCodes,
        IUserPasswordHistoryRepository passwordHistories,
        IRefreshTokenRepository refreshTokens,
        IDateTimeProvider clock,
        IIdentityRateLimiter rateLimiter)
    {
        _userManager = userManager;
        _resetCodes = resetCodes;
        _passwordHistories = passwordHistories;
        _refreshTokens = refreshTokens;
        _clock = clock;
        _rateLimiter = rateLimiter;
    }

    public async Task<PasswordResetResultDto> Handle(ResetPasswordCommand request, CancellationToken cancellationToken)
    {
        var accountKey = request.Email.Trim().ToLowerInvariant();
        var context = new ResetPasswordRateLimitContext(accountKey, request.ResetToken, request.IpAddress);

        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user is null)
        {
            var outcome = await _rateLimiter.RegisterResetPasswordAsync(context, succeeded: false, cancellationToken);
            await ApplyOutcomeAsync(outcome, cancellationToken);
            return PasswordResetResultDto.SuccessResult("If an account with that email exists, its password has been updated.");
        }

        var resetCode = await _resetCodes.GetLatestForUserAsync(user.Id, cancellationToken);
        if (resetCode is null || resetCode.IsExpired(_clock.UtcNow))
        {
            var outcome = await _rateLimiter.RegisterResetPasswordAsync(context, succeeded: false, cancellationToken);
            await ApplyOutcomeAsync(outcome, cancellationToken);
            return PasswordResetResultDto.FailureResult(IdentityRateLimitMessages.GenericError);
        }

        var verification = _userManager.PasswordHasher.VerifyHashedPassword(
            user,
            resetCode.CodeHash,
            request.VerificationCode
        );

        if (verification is not PasswordVerificationResult.Success and not PasswordVerificationResult.SuccessRehashNeeded)
        {
            var outcome = await _rateLimiter.RegisterResetPasswordAsync(context, succeeded: false, cancellationToken);
            await ApplyOutcomeAsync(outcome, cancellationToken);
            return PasswordResetResultDto.FailureResult(IdentityRateLimitMessages.GenericError);
        }

        var recentPasswords = await _passwordHistories.GetRecentAsync(user.Id, 5, cancellationToken);

        foreach (var previous in recentPasswords)
        {
            var previousVerification = _userManager.PasswordHasher.VerifyHashedPassword(user, previous.PasswordHash, request.NewPassword);
            if (previousVerification is PasswordVerificationResult.Success or PasswordVerificationResult.SuccessRehashNeeded)
            {
                var outcome = await _rateLimiter.RegisterResetPasswordAsync(context, succeeded: false, cancellationToken);
                await ApplyOutcomeAsync(outcome, cancellationToken);
                return PasswordResetResultDto.FailureResult(IdentityRateLimitMessages.GenericError);
            }
        }

        if (!string.IsNullOrEmpty(user.PasswordHash))
        {
            var currentVerification = _userManager.PasswordHasher.VerifyHashedPassword(user, user.PasswordHash, request.NewPassword);
            if (currentVerification is PasswordVerificationResult.Success or PasswordVerificationResult.SuccessRehashNeeded)
            {
                var outcome = await _rateLimiter.RegisterResetPasswordAsync(context, succeeded: false, cancellationToken);
                await ApplyOutcomeAsync(outcome, cancellationToken);
                return PasswordResetResultDto.FailureResult(IdentityRateLimitMessages.GenericError);
            }
        }

        var previousPasswordHash = user.PasswordHash;

        var result = await _userManager.ResetPasswordAsync(user, request.ResetToken, request.NewPassword);
        if (!result.Succeeded)
        {
            var description = string.Join("; ", result.Errors.Select(error => error.Description));
            _ = description;
            var outcome = await _rateLimiter.RegisterResetPasswordAsync(context, succeeded: false, cancellationToken);
            await ApplyOutcomeAsync(outcome, cancellationToken);
            return PasswordResetResultDto.FailureResult(IdentityRateLimitMessages.GenericError);
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
        var successOutcome = await _rateLimiter.RegisterResetPasswordAsync(context, succeeded: true, cancellationToken);
        await ApplyOutcomeAsync(successOutcome, cancellationToken);

        return PasswordResetResultDto.SuccessResult("Password reset successfully.");
    }

    private static async Task ApplyOutcomeAsync(RateLimitOutcome outcome, CancellationToken cancellationToken)
    {
        if (!outcome.IsAllowed)
        {
            throw new RateLimitException(outcome.Action, outcome.RetryAfter, outcome.LockDuration);
        }

        if (outcome.Delay is { } delay)
        {
            await Task.Delay(delay, cancellationToken);
        }
    }
}
