using Domain.Entities;
using Infrastructure.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Contexts;

public class JwtNetDbContext
    : IdentityDbContext<ApplicationUser, IdentityRole<Guid>, Guid,
                        IdentityUserClaim<Guid>, IdentityUserRole<Guid>,
                        IdentityUserLogin<Guid>, IdentityRoleClaim<Guid>,
                        IdentityUserToken<Guid>>
{
    public JwtNetDbContext(DbContextOptions<JwtNetDbContext> options) : base(options) { }

    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
    public DbSet<UserPasswordHistory> UserPasswordHistories => Set<UserPasswordHistory>();
    public DbSet<UserLoginHistory> UserLoginHistories => Set<UserLoginHistory>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.MapIdentityTables();

        builder.ApplyConfigurationsFromAssembly(typeof(JwtNetDbContext).Assembly);
    }
}
