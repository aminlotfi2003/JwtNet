using Application.Abstractions.Repositories;
using Application.Identity.DTOs;
using MediatR;

namespace Application.Identity.Queries.GetUserLoginHistory;

internal sealed class GetUserLoginHistoryQueryHandler : IRequestHandler<GetUserLoginHistoryQuery, IReadOnlyCollection<UserLoginHistoryDto>>
{
    private readonly IUserLoginHistoryRepository _loginHistories;

    public GetUserLoginHistoryQueryHandler(IUserLoginHistoryRepository loginHistories)
    {
        _loginHistories = loginHistories;
    }

    public async Task<IReadOnlyCollection<UserLoginHistoryDto>> Handle(GetUserLoginHistoryQuery request, CancellationToken cancellationToken)
    {
        var histories = await _loginHistories.GetRecentAsync(request.UserId, request.Count, cancellationToken);
        return histories
            .Select(UserLoginHistoryDto.FromEntity)
            .ToList();
    }
}
