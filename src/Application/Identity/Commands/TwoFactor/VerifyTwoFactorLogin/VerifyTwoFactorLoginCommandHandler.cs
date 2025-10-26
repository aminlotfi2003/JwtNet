using Application.Abstractions.Repositories;
using Application.Abstractions.Services;
using Application.Common.Exceptions;
using Application.Identity.DTOs;
using Application.Identity.RateLimiting;
using Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace Application.Identity.Commands.TwoFactor.VerifyTwoFactorLogin;

internal sealed class VerifyTwoFactorLoginCommandHandler : IRequestHandler<VerifyTwoFactorLoginCommand, AuthenticationResultDto>
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IRefreshTokenRepository _refreshTokens;
    private readonly IUserLoginHistoryRepository _loginHistories;
    private readonly ITokenService _tokenService;
    private readonly IDateTimeProvider _clock;
    private readonly IIdentityRateLimiter _rateLimiter;

    public VerifyTwoFactorLoginCommandHandler(
        UserManager<ApplicationUser> userManager,
        IRefreshTokenRepository refreshTokens,
        IUserLoginHistoryRepository loginHistories,
        ITokenService tokenService,
        IDateTimeProvider clock,
        IIdentityRateLimiter rateLimiter)
    {
        _userManager = userManager;
        _refreshTokens = refreshTokens;
        _loginHistories = loginHistories;
        _tokenService = tokenService;
        _clock = clock;
        _rateLimiter = rateLimiter;
    }

    public async Task<AuthenticationResultDto> Handle(VerifyTwoFactorLoginCommand request, CancellationToken cancellationToken)
    {
        var challengeKey = request.ChallengeId ?? request.UserId.ToString();
        var accountKey = request.UserId.ToString();
        var user = await _userManager.FindByIdAsync(request.UserId.ToString());
        if (user is null)
        {
            var outcome = await _rateLimiter.RegisterTwoFactorAttemptAsync(
                new TwoFactorRateLimitContext(challengeKey, accountKey, request.IpAddress),
                succeeded: false,
                cancellationToken);
            await ApplyOutcomeAsync(outcome, cancellationToken);
            throw new UnauthorizedException(IdentityRateLimitMessages.GenericError);
        }

        if (!user.TwoFactorEnabled)
        {
            var outcome = await _rateLimiter.RegisterTwoFactorAttemptAsync(
                new TwoFactorRateLimitContext(challengeKey, accountKey, request.IpAddress),
                succeeded: false,
                cancellationToken);
            await ApplyOutcomeAsync(outcome, cancellationToken);
            throw new BadRequestException(IdentityRateLimitMessages.GenericError);
        }

        var isValidToken = await _userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider, request.Token);
        if (!isValidToken)
        {
            var outcome = await _rateLimiter.RegisterTwoFactorAttemptAsync(
                new TwoFactorRateLimitContext(challengeKey, accountKey, request.IpAddress),
                succeeded: false,
                cancellationToken);
            await ApplyOutcomeAsync(outcome, cancellationToken);
            throw new UnauthorizedException(IdentityRateLimitMessages.GenericError);
        }

        var successOutcome = await _rateLimiter.RegisterTwoFactorAttemptAsync(
            new TwoFactorRateLimitContext(challengeKey, accountKey, request.IpAddress),
            succeeded: true,
            cancellationToken);
        await ApplyOutcomeAsync(successOutcome, cancellationToken);

        await _userManager.ResetAccessFailedCountAsync(user);

        await _refreshTokens.RevokeUserTokensAsync(user.Id, cancellationToken);

        var tokenPair = _tokenService.GenerateTokenPair(user);
        var refreshToken = Domain.Entities.RefreshToken.CreateHashed(user.Id, tokenPair.RefreshTokenHash, tokenPair.RefreshTokenExpiresAt);

        await _refreshTokens.AddAsync(refreshToken, cancellationToken);
        await _refreshTokens.SaveChangesAsync(cancellationToken);

        var loginHistory = UserLoginHistory.Create(
            user.Id,
            _clock.UtcNow,
            request.IpAddress,
            request.UserAgent);

        await _loginHistories.AddAsync(loginHistory, cancellationToken);
        await _loginHistories.SaveChangesAsync(cancellationToken);

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
