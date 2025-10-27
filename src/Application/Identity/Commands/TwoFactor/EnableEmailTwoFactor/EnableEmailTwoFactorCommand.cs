using MediatR;

namespace Application.Identity.Commands.TwoFactor.EnableEmailTwoFactor;

public sealed record EnableEmailTwoFactorCommand(Guid UserId, string Token, string? IpAddress) : IRequest;
