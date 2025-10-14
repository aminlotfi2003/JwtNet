using Application.Identity.DTOs;
using MediatR;

namespace Application.Identity.Commands.ActivateUser;

public sealed record ActivateUserCommand(Guid UserId) : IRequest<ApplicationUserDto>;
