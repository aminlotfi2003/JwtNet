using Application.Common.Exceptions;
using Application.Identity.RateLimiting;
using Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace Application.Identity.Commands.TwoFactor.EnableEmailTwoFactor;

internal sealed class EnableEmailTwoFactorCommandHandler : IRequestHandler<EnableEmailTwoFactorCommand>
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IIdentityRateLimiter _rateLimiter;

    public EnableEmailTwoFactorCommandHandler(UserManager<ApplicationUser> userManager, IIdentityRateLimiter rateLimiter)
    {
        _userManager = userManager;
        _rateLimiter = rateLimiter;
    }

    public async Task Handle(EnableEmailTwoFactorCommand request, CancellationToken cancellationToken)
    {
        var context = new TwoFactorEmailRateLimitContext(request.UserId.ToString(), request.IpAddress);
        var user = await _userManager.FindByIdAsync(request.UserId.ToString());
        if (user is null)
        {
            var outcome = await _rateLimiter.RegisterTwoFactorEmailEnableAsync(context, succeeded: false, cancellationToken);
            await ApplyOutcomeAsync(outcome, cancellationToken);
            throw new NotFoundException(IdentityRateLimitMessages.GenericError);
        }

        var isValidToken = await _userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider, request.Token);
        if (!isValidToken)
        {
            var failureOutcome = await _rateLimiter.RegisterTwoFactorEmailEnableAsync(context, succeeded: false, cancellationToken);
            await ApplyOutcomeAsync(failureOutcome, cancellationToken);
            throw new BadRequestException(IdentityRateLimitMessages.GenericError);
        }

        var enableOutcome = await _rateLimiter.RegisterTwoFactorEmailEnableAsync(context, succeeded: true, cancellationToken);
        await ApplyOutcomeAsync(enableOutcome, cancellationToken);

        var result = await _userManager.SetTwoFactorEnabledAsync(user, true);
        if (!result.Succeeded)
            throw new BadRequestException(IdentityRateLimitMessages.GenericError);
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