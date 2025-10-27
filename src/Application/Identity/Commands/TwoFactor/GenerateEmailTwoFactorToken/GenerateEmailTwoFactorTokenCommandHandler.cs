using Application.Common.Exceptions;
using Application.Identity.DTOs;
using Application.Identity.RateLimiting;
using Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace Application.Identity.Commands.TwoFactor.GenerateEmailTwoFactorToken;

internal sealed class GenerateEmailTwoFactorTokenCommandHandler : IRequestHandler<GenerateEmailTwoFactorTokenCommand, TwoFactorTokenDto>
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IIdentityRateLimiter _rateLimiter;

    public GenerateEmailTwoFactorTokenCommandHandler(UserManager<ApplicationUser> userManager, IIdentityRateLimiter rateLimiter)
    {
        _userManager = userManager;
        _rateLimiter = rateLimiter;
    }

    public async Task<TwoFactorTokenDto> Handle(GenerateEmailTwoFactorTokenCommand request, CancellationToken cancellationToken)
    {
        var user = await _userManager.FindByIdAsync(request.UserId.ToString());
        if (user is null)
            throw new NotFoundException(IdentityRateLimitMessages.GenericError);

        var rateOutcome = await _rateLimiter.RegisterTwoFactorEmailGenerateAsync(
            new TwoFactorEmailRateLimitContext(request.UserId.ToString(), request.IpAddress),
            cancellationToken);
        await ApplyOutcomeAsync(rateOutcome, cancellationToken);

        if (string.IsNullOrWhiteSpace(user.Email))
            throw new BadRequestException(IdentityRateLimitMessages.GenericError);

        var token = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);
        return new TwoFactorTokenDto(token);
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
