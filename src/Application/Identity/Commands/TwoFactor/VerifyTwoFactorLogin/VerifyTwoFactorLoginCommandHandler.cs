using Application.Abstractions.Services;
using Application.Identity.DTOs;
using Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace Application.Identity.Commands.TwoFactor.VerifyTwoFactorLogin;

internal sealed class VerifyTwoFactorLoginCommandHandler : IRequestHandler<VerifyTwoFactorLoginCommand, AuthenticationResultDto>
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IAuthenticationResultService _authenticationResultService;


    public VerifyTwoFactorLoginCommandHandler(
        UserManager<ApplicationUser> userManager,
        IAuthenticationResultService authenticationResultService)
    {
        _userManager = userManager;
        _authenticationResultService = authenticationResultService;
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

        return await _authenticationResultService.CreateAsync(
            user,
            request.IpAddress,
            request.UserAgent,
            cancellationToken
        );
    }
}
