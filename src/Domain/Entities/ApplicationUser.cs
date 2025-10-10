namespace Domain.Entities;

public class ApplicationUser
{
    public int Id { get; set; }

    public string UserName { get; set; } = default!;
    public string Email { get; set; } = default!;
    public string PasswordHash { get; set; } = default!;

    // Auditable
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }

    public ApplicationUser() { } // For EF Core
}
