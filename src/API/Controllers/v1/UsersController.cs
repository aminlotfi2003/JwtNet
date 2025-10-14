using Application.Identity.Commands.ActivateUser;
using Application.Identity.Commands.DeactivateUser;
using Application.Identity.DTOs;
using Application.Identity.Queries.GetUserById;
using Application.Identity.Queries.ListUsers;
using MediatR;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers.v1;

[ApiController]
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/users")]
public sealed class UsersController(IMediator mediator) : ControllerBase
{
    private readonly IMediator _mediator = mediator;

    #region List Users
    [HttpGet]
    public async Task<ActionResult<IReadOnlyCollection<ApplicationUserDto>>> ListUsers([FromQuery] bool includeInactive = true)
    {
        var users = await _mediator.Send(new ListUsersQuery(includeInactive));
        return Ok(users);
    }
    #endregion

    #region Get User By Id
    [HttpGet("{userId:guid}")]
    public async Task<ActionResult<ApplicationUserDto>> GetUser(Guid userId)
    {
        var user = await _mediator.Send(new GetUserByIdQuery(userId));
        return user is null ? NotFound() : Ok(user);
    }
    #endregion

    #region Activate User
    [HttpPost("{userId:guid}/activate")]
    public async Task<ActionResult<ApplicationUserDto>> ActivateUser(Guid userId)
    {
        try
        {
            var user = await _mediator.Send(new ActivateUserCommand(userId));
            return Ok(user);
        }
        catch (InvalidOperationException)
        {
            return NotFound();
        }
    }
    #endregion

    #region Deactivate
    [HttpPost("{userId:guid}/deactivate")]
    public async Task<ActionResult<ApplicationUserDto>> DeactivateUser(Guid userId)
    {
        try
        {
            var user = await _mediator.Send(new DeactivateUserCommand(userId));
            return Ok(user);
        }
        catch (InvalidOperationException)
        {
            return NotFound();
        }
    }
    #endregion
}
