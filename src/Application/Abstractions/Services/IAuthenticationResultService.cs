using Application.Identity.DTOs;
using Domain.Entities;

namespace Application.Abstractions.Services;

public interface IAuthenticationResultService
{
    Task<AuthenticationResultDto> CreateAsync(
        ApplicationUser user,
        string? ipAddress,
        string? userAgent,
        CancellationToken cancellationToken = default);
}
