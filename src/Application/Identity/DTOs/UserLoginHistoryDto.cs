using Domain.Entities;

namespace Application.Identity.DTOs;

public sealed record UserLoginHistoryDto(
    Guid Id,
    DateTimeOffset LoggedInAt,
    string? IpAddress,
    string? UserAgent)
{
    public static UserLoginHistoryDto FromEntity(UserLoginHistory history) => new(
        history.Id,
        history.LoggedInAt,
        history.IpAddress,
        history.UserAgent);
}
