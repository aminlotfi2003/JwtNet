using Application.Abstractions.Repositories;
using Application.Abstractions.Services;
using Application.Identity.DTOs;
using Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace Application.Identity.Commands.ChangePassword;

internal sealed class ChangePasswordCommandHandler : IRequestHandler<ChangePasswordCommand, AuthenticationResultDto>
{
    private static readonly TimeSpan RequiredInterval = TimeSpan.FromDays(90);

    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IRefreshTokenRepository _refreshTokens;
    private readonly ITokenService _tokenService;
    private readonly IDateTimeProvider _clock;

    public ChangePasswordCommandHandler(
        UserManager<ApplicationUser> userManager,
        IRefreshTokenRepository refreshTokens,
        ITokenService tokenService,
        IDateTimeProvider clock)
    {
        _userManager = userManager;
        _refreshTokens = refreshTokens;
        _tokenService = tokenService;
        _clock = clock;
    }

    public async Task<AuthenticationResultDto> Handle(ChangePasswordCommand request, CancellationToken cancellationToken)
    {
        var user = await _userManager.FindByIdAsync(request.UserId.ToString());
        if (user is null)
            throw new InvalidOperationException("User not found.");

        if (user.LastPasswordChangedAt.HasValue)
        {
            var elapsed = _clock.UtcNow - user.LastPasswordChangedAt.Value;
            if (elapsed < RequiredInterval)
                throw new InvalidOperationException("Passwords can only be changed once every 90 days.");
        }

        var result = await _userManager.ChangePasswordAsync(user, request.CurrentPassword, request.NewPassword);
        if (!result.Succeeded)
        {
            var description = string.Join("; ", result.Errors.Select(e => e.Description));
            throw new InvalidOperationException($"Unable to change password: {description}");
        }

        user.LastPasswordChangedAt = _clock.UtcNow;
        await _userManager.UpdateAsync(user);

        await _refreshTokens.RevokeUserTokensAsync(user.Id, cancellationToken);

        var tokenPair = _tokenService.GenerateTokenPair(user);
        var refreshToken = Domain.Entities.RefreshToken.CreateHashed(user.Id, tokenPair.RefreshTokenHash, tokenPair.RefreshTokenExpiresAt);

        await _refreshTokens.AddAsync(refreshToken, cancellationToken);
        await _refreshTokens.SaveChangesAsync(cancellationToken);

        return AuthenticationResultDto.FromTokenPair(tokenPair);
    }
}
