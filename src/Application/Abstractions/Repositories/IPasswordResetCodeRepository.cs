using Domain.Entities;

namespace Application.Abstractions.Repositories;

public interface IPasswordResetCodeRepository
{
    Task AddAsync(PasswordResetCode code, CancellationToken cancellationToken = default);
    Task<PasswordResetCode?> GetLatestForUserAsync(Guid userId, CancellationToken cancellationToken = default);
    Task RemoveAllForUserAsync(Guid userId, CancellationToken cancellationToken = default);
    Task SaveChangesAsync(CancellationToken cancellationToken = default);
}
