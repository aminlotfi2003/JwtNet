using Application.Identity.DTOs;
using Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Application.Identity.Queries.ListUsers;

internal sealed class ListUsersQueryHandler : IRequestHandler<ListUsersQuery, IReadOnlyCollection<ApplicationUserDto>>
{
    private readonly UserManager<ApplicationUser> _userManager;

    public ListUsersQueryHandler(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }

    public async Task<IReadOnlyCollection<ApplicationUserDto>> Handle(ListUsersQuery request, CancellationToken cancellationToken)
    {
        var query = _userManager.Users.AsQueryable();

        if (!request.IncludeInactive)
        {
            query = query.Where(user => user.IsActived);
        }

        var users = await query
            .OrderBy(user => user.Email)
            .ToListAsync(cancellationToken);

        return users
            .Select(ApplicationUserDto.FromEntity)
            .ToList();
    }
}
