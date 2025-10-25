using Application.Abstractions.Repositories;
using Application.Common.Exceptions;
using Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace Application.Identity.Commands.DeleteUser;

internal sealed class DeleteUserCommandHandler : IRequestHandler<DeleteUserCommand>
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IRefreshTokenRepository _refreshTokens;

    public DeleteUserCommandHandler(
        UserManager<ApplicationUser> userManager,
        IRefreshTokenRepository refreshTokens)
    {
        _userManager = userManager;
        _refreshTokens = refreshTokens;
    }

    public async Task Handle(DeleteUserCommand request, CancellationToken cancellationToken)
    {
        var user = await _userManager.FindByIdAsync(request.UserId.ToString());
        if (user is null)
            throw new NotFoundException("User not found.");

        await _refreshTokens.RevokeUserTokensAsync(user.Id, cancellationToken);
        await _refreshTokens.SaveChangesAsync(cancellationToken);

        var result = await _userManager.DeleteAsync(user);
        if (!result.Succeeded)
        {
            var description = string.Join("; ", result.Errors.Select(error => error.Description));
            throw new BadRequestException($"Unable to delete user: {description}");
        }
    }
}
