using Application.Identity.DTOs;
using MediatR;

namespace Application.Identity.Commands.RefreshToken;

public sealed record RefreshTokenCommand(string RefreshToken, string? IpAddress, string? ClientId) : IRequest<AuthenticationResultDto>;
