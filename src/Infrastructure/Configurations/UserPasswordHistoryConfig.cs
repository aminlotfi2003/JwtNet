using Domain.Entities;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Configurations;

public class UserPasswordHistoryConfig : IEntityTypeConfiguration<UserPasswordHistory>
{
    public void Configure(EntityTypeBuilder<UserPasswordHistory> builder)
    {
        builder.ToTable("UserPasswordHistories");

        builder.HasKey(h => h.Id);

        builder.Property(h => h.PasswordHash)
            .IsRequired();

        builder.Property(h => h.CreatedAt)
            .IsRequired();

        builder.HasIndex(h => new { h.UserId, h.CreatedAt });

        builder.HasOne(h => h.User)
            .WithMany(u => u.PasswordHistories)
            .HasForeignKey(h => h.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
