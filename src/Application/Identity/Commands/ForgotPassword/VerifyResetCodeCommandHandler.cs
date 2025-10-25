using Application.Abstractions.Repositories;
using Application.Abstractions.Services;
using Application.Identity.DTOs;
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

    public VerifyResetCodeCommandHandler(
        UserManager<ApplicationUser> userManager,
        IPasswordResetCodeRepository resetCodes,
        IDateTimeProvider clock)
    {
        _userManager = userManager;
        _resetCodes = resetCodes;
        _clock = clock;
    }

    public async Task<PasswordResetCodeVerificationResultDto> Handle(
        VerifyResetCodeCommand request,
        CancellationToken cancellationToken)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user is null)
            return PasswordResetCodeVerificationResultDto.FailureResult("Invalid verification code.");

        var resetCode = await _resetCodes.GetLatestForUserAsync(user.Id, cancellationToken);
        if (resetCode is null)
            return PasswordResetCodeVerificationResultDto.FailureResult("Invalid verification code.");

        if (resetCode.IsExpired(_clock.UtcNow))
            return PasswordResetCodeVerificationResultDto.FailureResult("The verification code has expired. Please request a new one.");

        var verification = _userManager.PasswordHasher.VerifyHashedPassword(
            user,
            resetCode.CodeHash,
            request.VerificationCode);

        if (verification is not PasswordVerificationResult.Success and not PasswordVerificationResult.SuccessRehashNeeded)
            return PasswordResetCodeVerificationResultDto.FailureResult("Invalid verification code.");

        if (resetCode.VerifiedAt is null)
        {
            resetCode.MarkVerified(_clock.UtcNow);
            await _resetCodes.SaveChangesAsync(cancellationToken);
        }

        return PasswordResetCodeVerificationResultDto.SuccessResult("Verification successful. You can now reset your password.");
    }
}
