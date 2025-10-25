using Domain.Entities;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Configurations;

public class PasswordResetCodeConfig : IEntityTypeConfiguration<PasswordResetCode>
{
    public void Configure(EntityTypeBuilder<PasswordResetCode> builder)
    {
        builder.ToTable("PasswordResetCodes");

        builder.HasKey(code => code.Id);

        builder.Property(code => code.CodeHash)
            .IsRequired()
            .HasMaxLength(256);

        builder.Property(code => code.CreatedAt)
            .IsRequired();

        builder.Property(code => code.ExpiresAt)
            .IsRequired();

        builder.HasOne(code => code.User)
            .WithMany(user => user.PasswordResetCodes)
            .HasForeignKey(code => code.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
