using Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Persistence;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<ApplicationUser> Users { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<ApplicationUser>(b =>
        {
            b.ToTable("Users");

            b.HasKey("Id");

            b.Property(x => x.UserName)
                .HasMaxLength(32)
                .IsRequired();

            b.Property(x => x.Email)
                .HasMaxLength(256)
                .IsRequired();

            b.Property(x => x.PasswordHash)
                .HasMaxLength(2048)
                .IsRequired();
        });
    }
}
