using Domain.Entities;

namespace API.Contracts.Identity;

public sealed record RegisterUserRequest(
    string Email,
    string Password,
    string ConfirmPassword,
    string FirstName,
    string LastName,
    Gender Gender,
    DateTimeOffset BirthDate
);
