using Application.Abstractions.Repositories;
using Domain.Entities;
using Infrastructure.Contexts;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Repositories;

public sealed class UserPasswordHistoryRepository(JwtNetDbContext context) : IUserPasswordHistoryRepository
{
    private readonly JwtNetDbContext _context = context;

    public async Task<IReadOnlyList<UserPasswordHistory>> GetRecentAsync(
        Guid userId,
        int count,
        CancellationToken cancellationToken = default)
    {
        return await _context.UserPasswordHistories
            .Where(history => history.UserId == userId)
            .OrderByDescending(history => history.CreatedAt)
            .Take(count)
            .ToListAsync(cancellationToken);
    }

    public async Task AddAsync(UserPasswordHistory history, CancellationToken cancellationToken = default)
    {
        await _context.UserPasswordHistories.AddAsync(history, cancellationToken);
    }

    public async Task PruneExcessAsync(Guid userId, int maxEntries, CancellationToken cancellationToken = default)
    {
        var toRemove = await _context.UserPasswordHistories
            .Where(history => history.UserId == userId)
            .OrderByDescending(history => history.CreatedAt)
            .Skip(maxEntries)
            .ToListAsync(cancellationToken);

        if (toRemove.Count != 0)
            _context.UserPasswordHistories.RemoveRange(toRemove);
    }

    public Task SaveChangesAsync(CancellationToken cancellationToken = default)
        => _context.SaveChangesAsync(cancellationToken);
}
