using MediatR;

namespace Application.Identity.Commands.DeleteUser;

public sealed record DeleteUserCommand(Guid UserId) : IRequest;
