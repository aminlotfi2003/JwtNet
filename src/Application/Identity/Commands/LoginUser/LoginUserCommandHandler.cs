using Application.Abstractions.Repositories;
using Application.Abstractions.Services;
using Application.Identity.DTOs;
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

    public LoginUserCommandHandler(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        IRefreshTokenRepository refreshTokens,
        IUserLoginHistoryRepository loginHistories,
        ITokenService tokenService,
        IDateTimeProvider clock)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _refreshTokens = refreshTokens;
        _loginHistories = loginHistories;
        _tokenService = tokenService;
        _clock = clock;
    }

    public async Task<LoginResultDto> Handle(LoginUserCommand request, CancellationToken cancellationToken)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user is null)
            throw new InvalidOperationException("Invalid email or password.");

        if (!user.LockoutEnabled)
        {
            user.LockoutEnabled = true;
            await _userManager.UpdateAsync(user);
        }

        var signInResult = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
        if (signInResult.IsLockedOut)
            throw new InvalidOperationException("Account locked due to multiple failed login attempts. Please try again later.");

        if (signInResult.RequiresTwoFactor)
        {
            var twoFactorToken = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);
            return LoginResultDto.RequiresTwoFactorResponse(user.Id, TokenOptions.DefaultEmailProvider, twoFactorToken);
        }

        if (!signInResult.Succeeded)
            throw new InvalidOperationException("Invalid email or password.");

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
}
