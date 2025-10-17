namespace Domain.Entities;

public class UserLoginHistory
{
    private UserLoginHistory()
    {
    }

    private UserLoginHistory(Guid id, Guid userId, DateTimeOffset loggedInAt, string? ipAddress, string? userAgent)
    {
        Id = id;
        UserId = userId;
        LoggedInAt = loggedInAt;
        IpAddress = ipAddress;
        UserAgent = userAgent;
    }

    public Guid Id { get; private set; }
    public Guid UserId { get; private set; }
    public DateTimeOffset LoggedInAt { get; private set; }
    public string? IpAddress { get; private set; }
    public string? UserAgent { get; private set; }

    public ApplicationUser User { get; private set; } = null!;

    public static UserLoginHistory Create(Guid userId, DateTimeOffset loggedInAt, string? ipAddress, string? userAgent)
        => new(Guid.NewGuid(), userId, loggedInAt, ipAddress, userAgent);
}
