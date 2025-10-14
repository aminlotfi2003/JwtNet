using System.Security.Cryptography;

namespace Domain.Entities;

public class RefreshToken
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public ApplicationUser User { get; set; } = default!;
    public string TokenHash { get; set; } = default!;
    public DateTimeOffset ExpiresAt { get; set; }
    public bool Revoked { get; set; }

    private RefreshToken() { } // For EF

    public RefreshToken(Guid userId, string tokenHash, DateTimeOffset expiresAt)
    {
        UserId = userId;
        TokenHash = tokenHash;
        ExpiresAt = expiresAt;
        Revoked = false;
    }

    public static RefreshToken Issue(Guid userId, int days = 7)
        => new(userId,
               Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
               DateTimeOffset.UtcNow.AddDays(days)
        );

    public static RefreshToken CreateHashed(Guid userId, string tokenHash, DateTimeOffset expiresAt)
        => new(userId, tokenHash, expiresAt);

    public void Revoke() => Revoked = true;

    public bool IsExpired(DateTimeOffset utcNow) => ExpiresAt <= utcNow;

    public bool IsActive(DateTimeOffset utcNow) => !Revoked && !IsExpired(utcNow);
}
