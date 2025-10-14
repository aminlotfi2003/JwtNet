using Application.Identity.DTOs;
using MediatR;

namespace Application.Identity.Commands.DeactivateUser;

public sealed record DeactivateUserCommand(Guid UserId) : IRequest<ApplicationUserDto>;
