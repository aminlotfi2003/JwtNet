using API.Contracts.Identity;
using Application.Identity.Commands.ActivateUser;
using Application.Identity.Commands.AdminResetPassword;
using Application.Identity.Commands.DeactivateUser;
using Application.Identity.Commands.DeleteUser;
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
        var user = await _mediator.Send(new ActivateUserCommand(userId));
        return Ok(user);
    }
    #endregion

    #region Deactivate
    [HttpPost("{userId:guid}/deactivate")]
    public async Task<ActionResult<ApplicationUserDto>> DeactivateUser(Guid userId)
    {
        var user = await _mediator.Send(new DeactivateUserCommand(userId));
        return Ok(user);
    }
    #endregion

    #region Reset Password (Admin)
    [HttpPost("{userId:guid}/password/reset")]
    public async Task<ActionResult<ApplicationUserDto>> ResetPassword(Guid userId, AdminResetPasswordRequest request)
    {
        var user = await _mediator.Send(new AdminResetPasswordCommand(userId, request.NewPassword, request.ConfirmPassword));
        return Ok(user);
    }
    #endregion

    #region Delete User
    [HttpDelete("{userId:guid}")]
    public async Task<IActionResult> DeleteUser(Guid userId)
    {
        await _mediator.Send(new DeleteUserCommand(userId));
        return NoContent();
    }
    #endregion
}
