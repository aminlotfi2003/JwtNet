using Application.Abstractions.Repositories;
using Domain.Entities;
using Infrastructure.Contexts;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Repositories;

public sealed class UserLoginHistoryRepository(JwtNetDbContext context) : IUserLoginHistoryRepository
{
    private readonly JwtNetDbContext _context = context;

    public async Task<IReadOnlyList<UserLoginHistory>> GetRecentAsync(
        Guid userId,
        int count,
        CancellationToken cancellationToken = default)
    {
        count = count <= 0 ? 10 : count;

        return await _context.UserLoginHistories
            .Where(history => history.UserId == userId)
            .OrderByDescending(history => history.LoggedInAt)
            .Take(count)
            .ToListAsync(cancellationToken);
    }

    public async Task AddAsync(UserLoginHistory history, CancellationToken cancellationToken = default)
    {
        await _context.UserLoginHistories.AddAsync(history, cancellationToken);
    }

    public Task SaveChangesAsync(CancellationToken cancellationToken = default)
        => _context.SaveChangesAsync(cancellationToken);
}
