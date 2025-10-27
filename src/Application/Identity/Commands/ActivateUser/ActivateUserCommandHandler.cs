using Application.Common.Exceptions;
using Application.Identity.DTOs;
using Application.Identity.RateLimiting;
using Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace Application.Identity.Commands.ActivateUser;

internal sealed class ActivateUserCommandHandler : IRequestHandler<ActivateUserCommand, ApplicationUserDto>
{
    private readonly UserManager<ApplicationUser> _userManager;

    public ActivateUserCommandHandler(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }

    public async Task<ApplicationUserDto> Handle(ActivateUserCommand request, CancellationToken cancellationToken)
    {
        var user = await _userManager.FindByIdAsync(request.UserId.ToString());
        if (user is null)
            throw new NotFoundException(IdentityRateLimitMessages.GenericError);

        if (!user.IsActived)
        {
            user.IsActived = true;
            user.LockoutEnd = null;

            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                var description = string.Join("; ", result.Errors.Select(e => e.Description));
                _ = description;
                throw new BadRequestException(IdentityRateLimitMessages.GenericError);
            }
        }

        return ApplicationUserDto.FromEntity(user);
    }
}
