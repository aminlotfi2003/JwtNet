using Domain.Entities;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Configurations;

public class ApplicationUserConfig : IEntityTypeConfiguration<ApplicationUser>
{
    public void Configure(EntityTypeBuilder<ApplicationUser> builder)
    {
        builder.ToTable("Users");

        // Property
        builder.Property(x => x.FirstName).HasMaxLength(100).IsRequired();
        builder.Property(x => x.LastName).HasMaxLength(100).IsRequired();
        builder.Property(x => x.Gender).IsRequired();
        builder.Property(x => x.BirthDate).IsRequired();
        builder.Property(x => x.IsActived).IsRequired();
        builder.Property(x => x.LastPasswordChangedAt).IsRequired(false);

        // Index
        builder.HasIndex(x => x.FirstName);
        builder.HasIndex(x => x.LastName);
        builder.HasIndex(x => x.BirthDate);
        builder.HasIndex(X => X.IsActived);
        builder.HasIndex(x => x.LastPasswordChangedAt);

        // Relation
        builder.HasMany(x => x.RefreshTokens)
            .WithOne(t => t.User)
            .HasForeignKey(x => x.UserId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasMany(x => x.PasswordHistories)
            .WithOne(h => h.User)
            .HasForeignKey(h => h.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
