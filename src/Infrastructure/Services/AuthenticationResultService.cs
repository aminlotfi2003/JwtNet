using Application.Abstractions.Repositories;
using Application.Abstractions.Services;
using Application.Identity.DTOs;
using Domain.Entities;

namespace Infrastructure.Services;

internal sealed class AuthenticationResultService : IAuthenticationResultService
{
    private readonly IRefreshTokenRepository _refreshTokens;
    private readonly IUserLoginHistoryRepository _loginHistories;
    private readonly ITokenService _tokenService;
    private readonly IDateTimeProvider _clock;

    public AuthenticationResultService(
        IRefreshTokenRepository refreshTokens,
        IUserLoginHistoryRepository loginHistories,
        ITokenService tokenService,
        IDateTimeProvider clock)
    {
        _refreshTokens = refreshTokens;
        _loginHistories = loginHistories;
        _tokenService = tokenService;
        _clock = clock;
    }

    public async Task<AuthenticationResultDto> CreateAsync(
        ApplicationUser user,
        string? ipAddress,
        string? userAgent,
        CancellationToken cancellationToken = default)
    {
        await _refreshTokens.RevokeUserTokensAsync(user.Id, cancellationToken);

        var tokenPair = _tokenService.GenerateTokenPair(user);
        var refreshToken = RefreshToken.CreateHashed(
            user.Id,
            tokenPair.RefreshTokenHash,
            tokenPair.RefreshTokenExpiresAt);

        await _refreshTokens.AddAsync(refreshToken, cancellationToken);
        await _refreshTokens.SaveChangesAsync(cancellationToken);

        var loginHistory = UserLoginHistory.Create(
            user.Id,
            _clock.UtcNow,
            ipAddress,
            userAgent);

        await _loginHistories.AddAsync(loginHistory, cancellationToken);
        await _loginHistories.SaveChangesAsync(cancellationToken);

        return AuthenticationResultDto.FromTokenPair(tokenPair);
    }
}
