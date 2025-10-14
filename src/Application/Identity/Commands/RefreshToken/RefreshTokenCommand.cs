using Application.Identity.DTOs;
using MediatR;

namespace Application.Identity.Commands.RefreshToken;

public sealed record RefreshTokenCommand(string RefreshToken) : IRequest<AuthenticationResultDto>;
