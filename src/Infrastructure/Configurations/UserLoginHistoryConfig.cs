using Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Configurations;

public class UserLoginHistoryConfig : IEntityTypeConfiguration<UserLoginHistory>
{
    public void Configure(EntityTypeBuilder<UserLoginHistory> builder)
    {
        builder.ToTable("UserLoginHistories");

        builder.HasKey(history => history.Id);

        builder.Property(history => history.LoggedInAt)
            .IsRequired();

        builder.Property(history => history.IpAddress)
            .HasMaxLength(256);

        builder.Property(history => history.UserAgent)
            .HasMaxLength(512);

        builder.HasIndex(history => new { history.UserId, history.LoggedInAt });

        builder.HasOne(history => history.User)
            .WithMany(user => user.LoginHistories)
            .HasForeignKey(history => history.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
