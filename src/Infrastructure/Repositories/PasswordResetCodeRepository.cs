using Application.Abstractions.Repositories;
using Domain.Entities;
using Infrastructure.Contexts;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Repositories;

public sealed class PasswordResetCodeRepository(JwtNetDbContext context) : IPasswordResetCodeRepository
{
    private readonly JwtNetDbContext _context = context;

    public async Task AddAsync(PasswordResetCode code, CancellationToken cancellationToken = default)
    {
        await _context.PasswordResetCodes.AddAsync(code, cancellationToken);
    }

    public async Task<PasswordResetCode?> GetLatestForUserAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        return await _context.PasswordResetCodes
            .Where(code => code.UserId == userId)
            .OrderByDescending(code => code.CreatedAt)
            .FirstOrDefaultAsync(cancellationToken);
    }

    public async Task RemoveAllForUserAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var codes = await _context.PasswordResetCodes
            .Where(code => code.UserId == userId)
            .ToListAsync(cancellationToken);

        if (codes.Count == 0)
            return;

        _context.PasswordResetCodes.RemoveRange(codes);
    }

    public async Task SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        await _context.SaveChangesAsync(cancellationToken);
    }
}
