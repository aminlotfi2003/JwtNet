using Application.Abstractions.Services;
using Application.Identity.DTOs;
using Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace Application.Identity.Commands.ExternalLogin;

internal sealed class ExternalLoginCommandHandler : IRequestHandler<ExternalLoginCommand, AuthenticationResultDto>
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IAuthenticationResultService _authenticationResultService;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public ExternalLoginCommandHandler(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        IAuthenticationResultService authenticationResultService,
        IHttpContextAccessor httpContextAccessor)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _authenticationResultService = authenticationResultService;
        _httpContextAccessor = httpContextAccessor;
    }

    public async Task<AuthenticationResultDto> Handle(ExternalLoginCommand request, CancellationToken cancellationToken)
    {
        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info is null)
            throw new InvalidOperationException("External login information could not be retrieved.");

        if (!string.Equals(info.LoginProvider, request.Provider, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("External login provider does not match the requested provider.");

        var signInResult = await _signInManager.ExternalLoginSignInAsync(
            info.LoginProvider,
            info.ProviderKey,
            isPersistent: false,
            bypassTwoFactor: true);

        ApplicationUser? user = null;

        if (signInResult.Succeeded)
        {
            user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
        }
        else
        {
            if (signInResult.IsLockedOut)
                throw new InvalidOperationException("Account locked due to multiple failed login attempts. Please try again later.");

            var email = info.Principal.FindFirstValue(ClaimTypes.Email) ??
                        info.Principal.FindFirstValue("email");

            if (string.IsNullOrWhiteSpace(email))
                throw new InvalidOperationException("The external provider did not return an email address.");

            user = await _userManager.FindByEmailAsync(email);
            if (user is null)
            {
                var firstName = info.Principal.FindFirstValue(ClaimTypes.GivenName);
                var lastName = info.Principal.FindFirstValue(ClaimTypes.Surname);
                var name = info.Principal.FindFirstValue("name");

                if (string.IsNullOrWhiteSpace(firstName) && !string.IsNullOrWhiteSpace(name))
                {
                    var nameParts = name.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (nameParts.Length > 0)
                    {
                        firstName = nameParts.First();
                        if (nameParts.Length > 1)
                            lastName = string.Join(' ', nameParts.Skip(1));
                    }
                }

                user = new ApplicationUser
                {
                    UserName = email,
                    Email = email,
                    EmailConfirmed = true,
                    FirstName = firstName,
                    LastName = lastName,
                    IsActived = true,
                    LockoutEnabled = true
                };

                var createUserResult = await _userManager.CreateAsync(user);
                if (!createUserResult.Succeeded)
                {
                    var description = string.Join("; ", createUserResult.Errors.Select(error => error.Description));
                    throw new InvalidOperationException($"Unable to create user from external login: {description}");
                }
            }

            await EnsureLoginAssociationAsync(user, info);
        }

        user ??= await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
        if (user is null)
            throw new InvalidOperationException("Unable to resolve user for external login.");

        await _signInManager.UpdateExternalAuthenticationTokensAsync(info);
        await _httpContextAccessor.HttpContext!.SignOutAsync(IdentityConstants.ExternalScheme);

        return await _authenticationResultService.CreateAsync(
            user,
            request.IpAddress,
            request.UserAgent,
            cancellationToken);
    }

    private async Task EnsureLoginAssociationAsync(ApplicationUser user, ExternalLoginInfo info)
    {
        var userLogins = await _userManager.GetLoginsAsync(user);
        if (userLogins.Any(login =>
                login.LoginProvider.Equals(info.LoginProvider, StringComparison.OrdinalIgnoreCase) &&
                login.ProviderKey.Equals(info.ProviderKey, StringComparison.Ordinal)))
        {
            return;
        }

        var addLoginResult = await _userManager.AddLoginAsync(user, info);
        if (!addLoginResult.Succeeded)
        {
            var description = string.Join("; ", addLoginResult.Errors.Select(error => error.Description));
            throw new InvalidOperationException($"Unable to associate external login: {description}");
        }
    }
}
