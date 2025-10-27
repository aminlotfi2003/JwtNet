using Application.Abstractions.Repositories;
using Application.Common.Exceptions;
using Application.Identity.DTOs;
using Application.Identity.RateLimiting;
using Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace Application.Identity.Commands.DeactivateUser;

internal sealed class DeactivateUserCommandHandler : IRequestHandler<DeactivateUserCommand, ApplicationUserDto>
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IRefreshTokenRepository _refreshTokens;

    public DeactivateUserCommandHandler(
        UserManager<ApplicationUser> userManager,
        IRefreshTokenRepository refreshTokens)
    {
        _userManager = userManager;
        _refreshTokens = refreshTokens;
    }

    public async Task<ApplicationUserDto> Handle(DeactivateUserCommand request, CancellationToken cancellationToken)
    {
        var user = await _userManager.FindByIdAsync(request.UserId.ToString());
        if (user is null)
            throw new NotFoundException(IdentityRateLimitMessages.GenericError);

        if (user.IsActived)
        {
            user.IsActived = false;
            user.LockoutEnd = DateTimeOffset.MaxValue;

            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                var description = string.Join("; ", result.Errors.Select(e => e.Description));
                _ = description;
                throw new BadRequestException(IdentityRateLimitMessages.GenericError);
            }

            await _refreshTokens.RevokeUserTokensAsync(user.Id, cancellationToken);
            await _refreshTokens.SaveChangesAsync(cancellationToken);
        }

        return ApplicationUserDto.FromEntity(user);
    }
}
