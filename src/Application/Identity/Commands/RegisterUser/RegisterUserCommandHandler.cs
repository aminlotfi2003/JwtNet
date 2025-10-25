using Application.Abstractions.Repositories;
using Application.Abstractions.Services;
using Application.Common.Exceptions;
using Application.Identity.DTOs;
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

    public RegisterUserCommandHandler(
        UserManager<ApplicationUser> userManager,
        ITokenService tokenService,
        IRefreshTokenRepository refreshTokens,
        IDateTimeProvider clock)
    {
        _userManager = userManager;
        _tokenService = tokenService;
        _refreshTokens = refreshTokens;
        _clock = clock;
    }

    public async Task<AuthenticationResultDto> Handle(RegisterUserCommand request, CancellationToken cancellationToken)
    {
        var existingUser = await _userManager.FindByEmailAsync(request.Email);
        if (existingUser is not null)
            throw new ConflictException("A user with the provided email address already exists.");

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
            throw new BadRequestException($"Unable to register user: {description}");
        }

        var tokenPair = _tokenService.GenerateTokenPair(user);
        var refreshToken = Domain.Entities.RefreshToken.CreateHashed(user.Id, tokenPair.RefreshTokenHash, tokenPair.RefreshTokenExpiresAt);

        await _refreshTokens.AddAsync(refreshToken, cancellationToken);
        await _refreshTokens.SaveChangesAsync(cancellationToken);

        return AuthenticationResultDto.FromTokenPair(tokenPair);
    }
}
