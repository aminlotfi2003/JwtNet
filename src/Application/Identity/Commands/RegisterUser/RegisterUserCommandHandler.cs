using Application.Abstractions.Repositories;
using Application.Abstractions.Services;
using Application.Common.Exceptions;
using Application.Identity.DTOs;
using Application.Identity.RateLimiting;
using Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace Application.Identity.Commands.RegisterUser;

internal sealed class RegisterUserCommandHandler : IRequestHandler<RegisterUserCommand, AuthenticationResultDto>
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ITokenService _tokenService;
    private readonly IRefreshTokenRepository _refreshTokens;
    private readonly IDateTimeProvider _clock;
    private readonly IIdentityRateLimiter _rateLimiter;
    private readonly IDisposableEmailDomainService _disposableDomainService;

    public RegisterUserCommandHandler(
        UserManager<ApplicationUser> userManager,
        ITokenService tokenService,
        IRefreshTokenRepository refreshTokens,
        IDateTimeProvider clock,
        IIdentityRateLimiter rateLimiter,
        IDisposableEmailDomainService disposableDomainService)
    {
        _userManager = userManager;
        _tokenService = tokenService;
        _refreshTokens = refreshTokens;
        _clock = clock;
        _rateLimiter = rateLimiter;
        _disposableDomainService = disposableDomainService;
    }

    public async Task<AuthenticationResultDto> Handle(RegisterUserCommand request, CancellationToken cancellationToken)
    {
        var domain = ExtractDomain(request.Email);
        var isDisposableDomain = domain is not null && _disposableDomainService.IsDisposable(domain);

        var rateOutcome = await _rateLimiter.EnforceRegisterAsync(
            new RegisterRateLimitContext(
                request.IpAddress,
                request.Asn,
                domain,
                request.TenantId,
                isDisposableDomain),
            cancellationToken);

        await ApplyOutcomeAsync(rateOutcome, cancellationToken);

        var existingUser = await _userManager.FindByEmailAsync(request.Email);
        if (existingUser is not null)
            throw new ConflictException(IdentityRateLimitMessages.GenericError);


        var user = new ApplicationUser
        {
            UserName = request.Email,
            Email = request.Email,
            FirstName = request.FirstName,
            LastName = request.LastName,
            Gender = request.Gender,
            BirthDate = request.BirthDate,
            IsActived = true,
            LastPasswordChangedAt = _clock.UtcNow,
            LockoutEnabled = true
        };

        var result = await _userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
        {
            var description = string.Join("; ", result.Errors.Select(e => e.Description));
            _ = description;
            throw new BadRequestException(IdentityRateLimitMessages.GenericError);
        }

        var tokenPair = _tokenService.GenerateTokenPair(user);
        var refreshToken = Domain.Entities.RefreshToken.CreateHashed(user.Id, tokenPair.RefreshTokenHash, tokenPair.RefreshTokenExpiresAt);

        await _refreshTokens.AddAsync(refreshToken, cancellationToken);
        await _refreshTokens.SaveChangesAsync(cancellationToken);

        return AuthenticationResultDto.FromTokenPair(tokenPair);
    }

    private static string? ExtractDomain(string email)
    {
        var atIndex = email.LastIndexOf('@');
        if (atIndex <= 0 || atIndex == email.Length - 1)
        {
            return null;
        }

        return email[(atIndex + 1)..].ToLowerInvariant();
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
