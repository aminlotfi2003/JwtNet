using System.Globalization;
using System.Security.Cryptography;
using Application.Abstractions.Repositories;
using Application.Abstractions.Services;
using Application.Identity.DTOs;
using Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace Application.Identity.Commands.ForgotPassword;

internal sealed class ForgotPasswordCommandHandler : IRequestHandler<ForgotPasswordCommand, ForgotPasswordTokenDto>
{
    private const int VerificationCodeLength = 6;
    private static readonly TimeSpan VerificationCodeLifetime = TimeSpan.FromMinutes(15);
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IPasswordResetCodeRepository _resetCodes;
    private readonly IPasswordResetCodeNotificationService _notificationService;
    private readonly IDateTimeProvider _clock;

    public ForgotPasswordCommandHandler(
        UserManager<ApplicationUser> userManager,
        IPasswordResetCodeRepository resetCodes,
        IPasswordResetCodeNotificationService notificationService,
        IDateTimeProvider clock)
    {
        _userManager = userManager;
        _resetCodes = resetCodes;
        _notificationService = notificationService;
        _clock = clock;
    }

    public async Task<ForgotPasswordTokenDto> Handle(ForgotPasswordCommand request, CancellationToken cancellationToken)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user is null)
        {
            const string notFoundMessage = "If an account with that email address exists, a verification code has been generated.";
            return ForgotPasswordTokenDto.SuccessWithoutToken(notFoundMessage);
        }

        var now = _clock.UtcNow;
        var expiresAt = now.Add(VerificationCodeLifetime);

        await _resetCodes.RemoveAllForUserAsync(user.Id, cancellationToken);

        var verificationCode = GenerateVerificationCode();
        var hashedCode = _userManager.PasswordHasher.HashPassword(user, verificationCode);

        var passwordResetCode = PasswordResetCode.Create(user.Id, hashedCode, now, expiresAt);
        await _resetCodes.AddAsync(passwordResetCode, cancellationToken);
        await _resetCodes.SaveChangesAsync(cancellationToken);
        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        var message = $"Enter the verification code sent to {user.Email} to continue. This code expires at {expiresAt:u}.";

        await _notificationService.NotifyAsync(user, token, verificationCode, expiresAt, cancellationToken);

        return ForgotPasswordTokenDto.SuccessWithToken(token, message, verificationCode);
    }

    private static string GenerateVerificationCode()
    {
        Span<byte> buffer = stackalloc byte[sizeof(uint)];
        RandomNumberGenerator.Fill(buffer);

        var numericValue = BitConverter.ToUInt32(buffer);
        var code = numericValue % 1_000_000u;

        return ((int)code).ToString($"D{VerificationCodeLength}", CultureInfo.InvariantCulture);
    }
}
