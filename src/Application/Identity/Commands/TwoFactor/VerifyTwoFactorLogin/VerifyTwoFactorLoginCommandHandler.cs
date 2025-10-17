using Application.Abstractions.Repositories;
using Application.Abstractions.Services;
using Application.Identity.DTOs;
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

    public VerifyTwoFactorLoginCommandHandler(
        UserManager<ApplicationUser> userManager,
        IRefreshTokenRepository refreshTokens,
        IUserLoginHistoryRepository loginHistories,
        ITokenService tokenService,
        IDateTimeProvider clock)
    {
        _userManager = userManager;
        _refreshTokens = refreshTokens;
        _loginHistories = loginHistories;
        _tokenService = tokenService;
        _clock = clock;
    }

    public async Task<AuthenticationResultDto> Handle(VerifyTwoFactorLoginCommand request, CancellationToken cancellationToken)
    {
        var user = await _userManager.FindByIdAsync(request.UserId.ToString());
        if (user is null)
            throw new InvalidOperationException("Invalid two-factor verification attempt.");

        if (!user.TwoFactorEnabled)
            throw new InvalidOperationException("Two-factor authentication is not enabled for this account.");

        var isValidToken = await _userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider, request.Token);
        if (!isValidToken)
            throw new InvalidOperationException("Invalid two-factor verification code.");

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
}
