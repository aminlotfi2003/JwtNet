using Application.Identity.DTOs;
using MediatR;

namespace Application.Identity.Commands.LoginUser;

public sealed record LoginUserCommand(
    string Email,
    string Password,
    string? IpAddress,
    string? UserAgent,
    string? DeviceId,
    bool IsHighRisk
) : IRequest<LoginResultDto>;
