using Application.Identity.DTOs;
using MediatR;

namespace Application.Identity.Commands.AdminResetPassword;

public sealed record AdminResetPasswordCommand(Guid UserId, string NewPassword, string ConfirmPassword)
    : IRequest<ApplicationUserDto>;
