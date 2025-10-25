using Application.Identity.DTOs;
using MediatR;

namespace Application.Identity.Commands.ResetPassword;

public sealed record ResetPasswordCommand(
    string Email,
    string ResetToken,
    string VerificationCode,
    string NewPassword,
    string ConfirmPassword
) : IRequest<PasswordResetResultDto>;
