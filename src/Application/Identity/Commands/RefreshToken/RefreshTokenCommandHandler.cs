using Application.Abstractions.Repositories;
using Application.Abstractions.Services;
using Application.Identity.DTOs;
using MediatR;

namespace Application.Identity.Commands.RefreshToken;

internal sealed class RefreshTokenCommandHandler : IRequestHandler<RefreshTokenCommand, AuthenticationResultDto>
{
    private readonly IRefreshTokenRepository _refreshTokens;
    private readonly ITokenService _tokenService;
    private readonly IDateTimeProvider _clock;

    public RefreshTokenCommandHandler(
        IRefreshTokenRepository refreshTokens,
        ITokenService tokenService,
        IDateTimeProvider clock)
    {
        _refreshTokens = refreshTokens;
        _tokenService = tokenService;
        _clock = clock;
    }

    public async Task<AuthenticationResultDto> Handle(RefreshTokenCommand request, CancellationToken cancellationToken)
    {
        var hashedToken = _tokenService.ComputeHash(request.RefreshToken);
        var storedToken = await _refreshTokens.GetByTokenHashAsync(hashedToken, cancellationToken);

        if (storedToken is null || !storedToken.IsActive(_clock.UtcNow))
            throw new InvalidOperationException("Invalid or expired refresh token.");

        storedToken.Revoke();

        var user = storedToken.User ?? throw new InvalidOperationException("Refresh token is no longer associated with a user.");

        var tokenPair = _tokenService.GenerateTokenPair(user);
        var newRefreshToken = Domain.Entities.RefreshToken.CreateHashed(
            user.Id,
            tokenPair.RefreshTokenHash,
            tokenPair.RefreshTokenExpiresAt
        );

        await _refreshTokens.AddAsync(newRefreshToken, cancellationToken);
        await _refreshTokens.SaveChangesAsync(cancellationToken);

        return AuthenticationResultDto.FromTokenPair(tokenPair);
    }
}
