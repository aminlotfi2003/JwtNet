using Application.Identity.DTOs;
using MediatR;

namespace Application.Identity.Queries.GetUserLoginHistory;

public sealed record GetUserLoginHistoryQuery(Guid UserId, int Count = 10) : IRequest<IReadOnlyCollection<UserLoginHistoryDto>>;
