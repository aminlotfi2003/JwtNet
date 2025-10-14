using MediatR;

namespace Application.Identity.Commands.LogoutUser;

public sealed record LogoutUserCommand(string RefreshToken) : IRequest;
