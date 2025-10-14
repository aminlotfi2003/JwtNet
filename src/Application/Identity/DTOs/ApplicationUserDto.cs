using Domain.Entities;

namespace Application.Identity.DTOs;

public sealed record ApplicationUserDto(
    Guid Id,
    string Email,
    string? FirstName,
    string? LastName,
    Gender? Gender,
    DateTimeOffset? BirthDate,
    bool IsActived,
    DateTimeOffset? LastPasswordChangedAt)
{
    public static ApplicationUserDto FromEntity(ApplicationUser user) =>
        new(
            user.Id,
            user.Email!,
            user.FirstName,
            user.LastName,
            user.Gender,
            user.BirthDate,
            user.IsActived,
            user.LastPasswordChangedAt
        );
}
