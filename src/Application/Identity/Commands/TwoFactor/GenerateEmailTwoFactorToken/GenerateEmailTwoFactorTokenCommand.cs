using Application.Identity.DTOs;
using MediatR;

namespace Application.Identity.Commands.TwoFactor.GenerateEmailTwoFactorToken;

public sealed record GenerateEmailTwoFactorTokenCommand(Guid UserId, string? IpAddress) : IRequest<TwoFactorTokenDto>;
