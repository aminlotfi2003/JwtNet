using Application.Abstractions.Repositories;
using Application.Abstractions.Services;
using Application.Common.Exceptions;
using Application.Identity.RateLimiting;
using MediatR;

namespace Application.Identity.Commands.LogoutUser;

internal sealed class LogoutUserCommandHandler : IRequestHandler<LogoutUserCommand>
{
    private readonly IRefreshTokenRepository _refreshTokens;
    private readonly ITokenService _tokenService;
    private readonly IDateTimeProvider _clock;
    private readonly IIdentityRateLimiter _rateLimiter;

    public LogoutUserCommandHandler(
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

    public async Task Handle(LogoutUserCommand request, CancellationToken cancellationToken)
    {
        var hashedToken = _tokenService.ComputeHash(request.RefreshToken);
        var storedToken = await _refreshTokens.GetByTokenHashAsync(hashedToken, cancellationToken);
        var accountKey = storedToken?.UserId.ToString();
        var rateOutcome = await _rateLimiter.RegisterLogoutAttemptAsync(
            new SimpleRateLimitContext(accountKey, request.IpAddress),
            cancellationToken);
        await ApplyOutcomeAsync(rateOutcome, cancellationToken);

        if (storedToken is null)
            return;

        if (storedToken.IsActive(_clock.UtcNow))
            storedToken.Revoke();
        await _refreshTokens.SaveChangesAsync(cancellationToken);
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
