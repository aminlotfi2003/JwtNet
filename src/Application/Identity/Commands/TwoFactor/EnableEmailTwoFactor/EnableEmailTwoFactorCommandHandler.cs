using Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace Application.Identity.Commands.TwoFactor.EnableEmailTwoFactor;

internal sealed class EnableEmailTwoFactorCommandHandler : IRequestHandler<EnableEmailTwoFactorCommand>
{
    private readonly UserManager<ApplicationUser> _userManager;

    public EnableEmailTwoFactorCommandHandler(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }

    public async Task Handle(EnableEmailTwoFactorCommand request, CancellationToken cancellationToken)
    {
        var user = await _userManager.FindByIdAsync(request.UserId.ToString());
        if (user is null)
            throw new InvalidOperationException("User not found.");

        var isValidToken = await _userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider, request.Token);
        if (!isValidToken)
            throw new InvalidOperationException("Invalid two-factor verification code.");

        var result = await _userManager.SetTwoFactorEnabledAsync(user, true);
        if (!result.Succeeded)
            throw new InvalidOperationException("Failed to enable two-factor authentication.");
    }
}
