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
    private readonly IAuthenticationResultService _authenticationResultService;

    public LoginUserCommandHandler(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        IAuthenticationResultService authenticationResultService)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _authenticationResultService = authenticationResultService;
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

        var authenticationResult = await _authenticationResultService.CreateAsync(
            user,
            request.IpAddress,
            request.UserAgent,
            cancellationToken
        );
        return LoginResultDto.Success(authenticationResult);
    }
}
