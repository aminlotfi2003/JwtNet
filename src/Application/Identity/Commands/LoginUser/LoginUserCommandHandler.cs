using Application.Abstractions.Repositories;
using Application.Abstractions.Services;
using Application.Common.Exceptions;
using Application.Identity.DTOs;
using Application.Identity.RateLimiting;
using Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace Application.Identity.Commands.LoginUser;

internal sealed class LoginUserCommandHandler : IRequestHandler<LoginUserCommand, LoginResultDto>
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IRefreshTokenRepository _refreshTokens;
    private readonly IUserLoginHistoryRepository _loginHistories;
    private readonly ITokenService _tokenService;
    private readonly IDateTimeProvider _clock;
    private readonly IIdentityRateLimiter _rateLimiter;

    public LoginUserCommandHandler(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        IRefreshTokenRepository refreshTokens,
        IUserLoginHistoryRepository loginHistories,
        ITokenService tokenService,
        IDateTimeProvider clock,
        IIdentityRateLimiter rateLimiter)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _refreshTokens = refreshTokens;
        _loginHistories = loginHistories;
        _tokenService = tokenService;
        _clock = clock;
        _rateLimiter = rateLimiter;
    }

    public async Task<LoginResultDto> Handle(LoginUserCommand request, CancellationToken cancellationToken)
    {
        var normalizedEmail = NormalizeEmail(request.Email);
        var rateContext = new LoginRateLimitContext(normalizedEmail, request.IpAddress, request.DeviceId, null, request.IsHighRisk);

        var preOutcome = await _rateLimiter.CheckLoginAsync(rateContext, cancellationToken);
        await ApplyOutcomeAsync(preOutcome, cancellationToken);

        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user is null)
        {
            var resultOutcome = await _rateLimiter.RegisterLoginResultAsync(rateContext, LoginAttemptOutcome.FailedInvalidCredentials, cancellationToken);
            await ApplyOutcomeAsync(resultOutcome, cancellationToken);
            throw new UnauthorizedException(IdentityRateLimitMessages.GenericError);
        }

        if (!user.LockoutEnabled)
        {
            user.LockoutEnabled = true;
            await _userManager.UpdateAsync(user);
        }

        var signInResult = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
        if (signInResult.IsLockedOut)
        {
            var lockedOutcome = await _rateLimiter.RegisterLoginResultAsync(rateContext, LoginAttemptOutcome.LockedOut, cancellationToken);
            await ApplyOutcomeAsync(lockedOutcome, cancellationToken);
            throw new LockedException(IdentityRateLimitMessages.GenericError);
        }

        if (signInResult.RequiresTwoFactor)
        {
            var twoFactorOutcome = await _rateLimiter.RegisterLoginResultAsync(rateContext, LoginAttemptOutcome.RequiresTwoFactor, cancellationToken);
            await ApplyOutcomeAsync(twoFactorOutcome, cancellationToken);
            var twoFactorToken = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);
            return LoginResultDto.RequiresTwoFactorResponse(user.Id, TokenOptions.DefaultEmailProvider, twoFactorToken);
        }

        if (!signInResult.Succeeded)
        {
            var failureOutcome = await _rateLimiter.RegisterLoginResultAsync(rateContext, LoginAttemptOutcome.FailedInvalidCredentials, cancellationToken);
            await ApplyOutcomeAsync(failureOutcome, cancellationToken);
            throw new UnauthorizedException(IdentityRateLimitMessages.GenericError);
        }

        var successOutcome = await _rateLimiter.RegisterLoginResultAsync(rateContext, LoginAttemptOutcome.Success, cancellationToken);
        await ApplyOutcomeAsync(successOutcome, cancellationToken);

        var authenticationResult = await GenerateAuthenticationResultAsync(user, request.IpAddress, request.UserAgent, cancellationToken);
        return LoginResultDto.Success(authenticationResult);
    }

    private async Task<AuthenticationResultDto> GenerateAuthenticationResultAsync(
        ApplicationUser user,
        string? ipAddress,
        string? userAgent,
        CancellationToken cancellationToken)
    {
        await _refreshTokens.RevokeUserTokensAsync(user.Id, cancellationToken);

        var tokenPair = _tokenService.GenerateTokenPair(user);
        var refreshToken = Domain.Entities.RefreshToken.CreateHashed(user.Id, tokenPair.RefreshTokenHash, tokenPair.RefreshTokenExpiresAt);

        await _refreshTokens.AddAsync(refreshToken, cancellationToken);
        await _refreshTokens.SaveChangesAsync(cancellationToken);

        var loginHistory = UserLoginHistory.Create(
            user.Id,
            _clock.UtcNow,
            ipAddress,
            userAgent
        );

        await _loginHistories.AddAsync(loginHistory, cancellationToken);
        await _loginHistories.SaveChangesAsync(cancellationToken);

        return AuthenticationResultDto.FromTokenPair(tokenPair);
    }

    private string NormalizeEmail(string email)
        => _userManager.NormalizeEmail(email) ?? email.Trim().ToUpperInvariant();

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
