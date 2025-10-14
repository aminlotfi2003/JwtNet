using Application.Identity.DTOs;
using MediatR;

namespace Application.Identity.Queries.ListUsers;

public sealed record ListUsersQuery(bool IncludeInactive = true) : IRequest<IReadOnlyCollection<ApplicationUserDto>>;
