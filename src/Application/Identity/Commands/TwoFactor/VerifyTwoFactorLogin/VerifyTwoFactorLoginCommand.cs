using Application.Identity.DTOs;
using MediatR;

namespace Application.Identity.Commands.TwoFactor.VerifyTwoFactorLogin;

public sealed record VerifyTwoFactorLoginCommand(
    Guid UserId,
    string Token,
    string? IpAddress,
    string? UserAgent,
    string? ChallengeId
) : IRequest<AuthenticationResultDto>;
