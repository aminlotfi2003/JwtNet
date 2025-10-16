using Application.Abstractions.Repositories;
using Application.Abstractions.Services;
using Application.Identity.DTOs;
using Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace Application.Identity.Commands.LoginUser;

internal sealed class LoginUserCommandHandler : IRequestHandler<LoginUserCommand, AuthenticationResultDto>
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IRefreshTokenRepository _refreshTokens;
    private readonly ITokenService _tokenService;

    public LoginUserCommandHandler(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        IRefreshTokenRepository refreshTokens,
        ITokenService tokenService)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _refreshTokens = refreshTokens;
        _tokenService = tokenService;
    }

    public async Task<AuthenticationResultDto> Handle(LoginUserCommand request, CancellationToken cancellationToken)
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

        if (!signInResult.Succeeded)
            throw new InvalidOperationException("Invalid email or password.");

        await _refreshTokens.RevokeUserTokensAsync(user.Id, cancellationToken);

        var tokenPair = _tokenService.GenerateTokenPair(user);
        var refreshToken = Domain.Entities.RefreshToken.CreateHashed(user.Id, tokenPair.RefreshTokenHash, tokenPair.RefreshTokenExpiresAt);

        await _refreshTokens.AddAsync(refreshToken, cancellationToken);
        await _refreshTokens.SaveChangesAsync(cancellationToken);

        return AuthenticationResultDto.FromTokenPair(tokenPair);
    }
}
