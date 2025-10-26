using Application.Abstractions.Repositories;
using Application.Abstractions.Services;
using Application.Common.Exceptions;
using Application.Identity.DTOs;
using Application.Identity.RateLimiting;
using Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace Application.Identity.Commands.ForgotPassword;

internal sealed class VerifyResetCodeCommandHandler
    : IRequestHandler<VerifyResetCodeCommand, PasswordResetCodeVerificationResultDto>
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IPasswordResetCodeRepository _resetCodes;
    private readonly IDateTimeProvider _clock;
    private readonly IIdentityRateLimiter _rateLimiter;

    public VerifyResetCodeCommandHandler(
        UserManager<ApplicationUser> userManager,
        IPasswordResetCodeRepository resetCodes,
        IDateTimeProvider clock,
        IIdentityRateLimiter rateLimiter)
    {
        _userManager = userManager;
        _resetCodes = resetCodes;
        _clock = clock;
        _rateLimiter = rateLimiter;
    }

    public async Task<PasswordResetCodeVerificationResultDto> Handle(
        VerifyResetCodeCommand request,
        CancellationToken cancellationToken)
    {
        var flowKey = $"{request.Email.Trim().ToLowerInvariant()}:{request.VerificationCode}";
        var user = await _userManager.FindByEmailAsync(request.Email);

        var outcomeResult = PasswordResetCodeVerificationResultDto.FailureResult(IdentityRateLimitMessages.GenericError);
        var succeeded = false;

        if (user is not null)
        {
            var resetCode = await _resetCodes.GetLatestForUserAsync(user.Id, cancellationToken);
            if (resetCode is not null && !resetCode.IsExpired(_clock.UtcNow))
            {
                var verification = _userManager.PasswordHasher.VerifyHashedPassword(
                    user,
                    resetCode.CodeHash,
                    request.VerificationCode);

                if (verification is PasswordVerificationResult.Success or PasswordVerificationResult.SuccessRehashNeeded)
                {
                    succeeded = true;
                    if (resetCode.VerifiedAt is null)
                    {
                        resetCode.MarkVerified(_clock.UtcNow);
                        await _resetCodes.SaveChangesAsync(cancellationToken);
                    }

                }
            }
            outcomeResult = PasswordResetCodeVerificationResultDto.SuccessResult("Verification successful.");
        }

        var rateOutcome = await _rateLimiter.RegisterForgotPasswordVerifyAsync(
            new VerifyResetRateLimitContext(flowKey, request.IpAddress),
            succeeded,
            cancellationToken);
        await ApplyOutcomeAsync(rateOutcome, cancellationToken);

        return outcomeResult;
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
