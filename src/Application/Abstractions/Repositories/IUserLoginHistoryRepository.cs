using Domain.Entities;

namespace Application.Abstractions.Repositories;

public interface IUserLoginHistoryRepository
{
    Task<IReadOnlyList<UserLoginHistory>> GetRecentAsync(Guid userId, int count, CancellationToken cancellationToken = default);
    Task AddAsync(UserLoginHistory history, CancellationToken cancellationToken = default);
    Task SaveChangesAsync(CancellationToken cancellationToken = default);
}
