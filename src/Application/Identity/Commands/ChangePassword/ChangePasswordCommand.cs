using Application.Identity.DTOs;
using MediatR;

namespace Application.Identity.Commands.ChangePassword;

public sealed record ChangePasswordCommand(
    Guid UserId,
    string CurrentPassword,
    string NewPassword,
    string? IpAddress
) : IRequest<AuthenticationResultDto>;
