using Application.Identity.DTOs;
using MediatR;

namespace Application.Identity.Commands.ForgotPassword;

public sealed record VerifyResetCodeCommand(string Email, string VerificationCode)
    : IRequest<PasswordResetCodeVerificationResultDto>;
