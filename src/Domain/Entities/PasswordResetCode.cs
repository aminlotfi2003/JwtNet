namespace Domain.Entities;

public class PasswordResetCode
{
    private PasswordResetCode(Guid userId, string codeHash, DateTimeOffset createdAt, DateTimeOffset expiresAt)
    {
        Id = Guid.NewGuid();
        UserId = userId;
        CodeHash = codeHash;
        CreatedAt = createdAt;
        ExpiresAt = expiresAt;
    }

    private PasswordResetCode() { }

    public Guid Id { get; private set; }
    public Guid UserId { get; private set; }
    public string CodeHash { get; private set; } = null!;
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset ExpiresAt { get; private set; }
    public DateTimeOffset? VerifiedAt { get; private set; }

    public ApplicationUser User { get; private set; } = null!;

    public static PasswordResetCode Create(Guid userId, string codeHash, DateTimeOffset createdAt, DateTimeOffset expiresAt) =>
        new(userId, codeHash, createdAt, expiresAt);

    public void MarkVerified(DateTimeOffset verifiedAt)
    {
        VerifiedAt = verifiedAt;
    }

    public bool IsExpired(DateTimeOffset utcNow) => utcNow > ExpiresAt;
}
