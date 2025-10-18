using Application.Identity.DTOs;
using MediatR;

namespace Application.Identity.Commands.ExternalLogin;

public sealed record ExternalLoginCommand(
    string Provider,
    string? IpAddress,
    string? UserAgent
) : IRequest<AuthenticationResultDto>;
