using Application.Identity.DTOs;
using MediatR;

namespace Application.Identity.Queries.GetUserById;

public sealed record GetUserByIdQuery(Guid UserId) : IRequest<ApplicationUserDto?>;
