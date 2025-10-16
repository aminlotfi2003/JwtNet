namespace Domain.Entities;

public class UserPasswordHistory
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public ApplicationUser User { get; set; } = null!;
    public string PasswordHash { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; }

    public static UserPasswordHistory Create(Guid userId, string passwordHash, DateTimeOffset createdAt)
        => new()
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            PasswordHash = passwordHash,
            CreatedAt = createdAt
        };
}
