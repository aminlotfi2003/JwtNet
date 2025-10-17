using Microsoft.AspNetCore.Identity;

namespace Domain.Entities;

public class ApplicationUser : IdentityUser<Guid>
{
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public Gender? Gender { get; set; }
    public DateTimeOffset? BirthDate { get; set; }
    public bool IsActived { get; set; }
    public DateTimeOffset? LastPasswordChangedAt { get; set; }
    public ICollection<RefreshToken> RefreshTokens { get; set; } = new HashSet<RefreshToken>();
    public ICollection<UserPasswordHistory> PasswordHistories { get; set; } = new HashSet<UserPasswordHistory>();
    public ICollection<UserLoginHistory> LoginHistories { get; set; } = new HashSet<UserLoginHistory>();
}

public enum Gender { Male, Female }
