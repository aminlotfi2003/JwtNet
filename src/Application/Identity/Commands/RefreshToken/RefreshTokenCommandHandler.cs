using Application.Abstractions.Repositories;
using Application.Abstractions.Services;
using Application.Common.Exceptions;
using Application.Identity.DTOs;
using Application.Identity.RateLimiting;
using MediatR;

namespace Application.Identity.Commands.RefreshToken;

internal sealed class RefreshTokenCommandHandler : IRequestHandler<RefreshTokenCommand, AuthenticationResultDto>
{
    private readonly IRefreshTokenRepository _refreshTokens;
    private readonly ITokenService _tokenService;
    private readonly IDateTimeProvider _clock;
    private readonly IIdentityRateLimiter _rateLimiter;

    public RefreshTokenCommandHandler(
        IRefreshTokenRepository refreshTokens,
        ITokenService tokenService,
        IDateTimeProvider clock,
        IIdentityRateLimiter rateLimiter)
    {
        _refreshTokens = refreshTokens;
        _tokenService = tokenService;
        _clock = clock;
        _rateLimiter = rateLimiter;
    }

    public async Task<AuthenticationResultDto> Handle(RefreshTokenCommand request, CancellationToken cancellationToken)
    {
        var hashedToken = _tokenService.ComputeHash(request.RefreshToken);
        var storedToken = await _refreshTokens.GetByTokenHashAsync(hashedToken, cancellationToken);

        var isActive = storedToken is not null && storedToken.IsActive(_clock.UtcNow);
        var sessionKey = storedToken?.Id.ToString() ?? hashedToken;
        var accountKey = storedToken?.UserId.ToString() ?? hashedToken;

        var rateOutcome = await _rateLimiter.RegisterRefreshAttemptAsync(
            new RefreshRateLimitContext(sessionKey, accountKey, request.ClientId, request.IpAddress),
            isActive,
            cancellationToken);
        await ApplyOutcomeAsync(rateOutcome, cancellationToken);

        if (!isActive)
            throw new UnauthorizedException(IdentityRateLimitMessages.GenericError);

        storedToken?.Revoke();

        var user = storedToken?.User ?? throw new UnauthorizedException(IdentityRateLimitMessages.GenericError);

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

    private static async Task ApplyOutcomeAsync(RateLimitOutcome outcome, CancellationToken cancellationToken)
    {
        if (!outcome.IsAllowed)
        {
            throw new RateLimitException(outcome.Action, outcome.RetryAfter, outcome.LockDuration);
        }

        if (outcome.Delay is { } delay)
        {
            await Task.Delay(delay, cancellationToken);
        }
    }
}
