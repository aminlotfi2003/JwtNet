using Application.Identity.DTOs;
using Domain.Entities;
using MediatR;

namespace Application.Identity.Commands.RegisterUser;

public sealed record RegisterUserCommand(
    string Email,
    string Password,
    string ConfirmPassword,
    string FirstName,
    string LastName,
    Gender Gender,
    DateTimeOffset BirthDate,
    string? IpAddress,
    string? Asn,
    string? TenantId
) : IRequest<AuthenticationResultDto>;
