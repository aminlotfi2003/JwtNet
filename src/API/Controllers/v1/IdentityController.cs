using API.Contracts.Identity;
using Application.Identity.Commands.ChangePassword;
using Application.Identity.Commands.ForgotPassword;
using Application.Identity.Commands.LoginUser;
using Application.Identity.Commands.LogoutUser;
using Application.Identity.Commands.RefreshToken;
using Application.Identity.Commands.RegisterUser;
using Application.Identity.DTOs;
using MediatR;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers.v1;

[ApiController]
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/identity")]
public sealed class IdentityController(IMediator mediator) : ControllerBase
{
    private readonly IMediator _mediator = mediator;

    #region Register
    [HttpPost("register")]
    public async Task<ActionResult<AuthenticationResultDto>> Register(RegisterUserRequest request)
    {
        try
        {
            var result = await _mediator.Send(new RegisterUserCommand(
                request.Email,
                request.Password,
                request.ConfirmPassword,
                request.FirstName,
                request.LastName,
                request.Gender,
                request.BirthDate));

            return Ok(result);
        }
        catch (InvalidOperationException ex)
        {
            return Conflict(new { message = ex.Message });
        }
    }
    #endregion

    #region Login
    [HttpPost("login")]
    public async Task<ActionResult<AuthenticationResultDto>> Login(LoginUserRequest request)
    {
        try
        {
            var result = await _mediator.Send(new LoginUserCommand(request.Email, request.Password));
            return Ok(result);
        }
        catch (InvalidOperationException ex)
        {
            return Unauthorized(new { message = ex.Message });
        }
    }
    #endregion

    #region Refresh
    [HttpPost("refresh")]
    public async Task<ActionResult<AuthenticationResultDto>> Refresh(RefreshTokenRequest request)
    {
        try
        {
            var result = await _mediator.Send(new RefreshTokenCommand(request.RefreshToken));
            return Ok(result);
        }
        catch (InvalidOperationException ex)
        {
            return Unauthorized(new { message = ex.Message });
        }
    }
    #endregion

    #region Logout
    [HttpPost("logout")]
    public async Task<IActionResult> Logout(LogoutUserRequest request)
    {
        await _mediator.Send(new LogoutUserCommand(request.RefreshToken));
        return NoContent();
    }
    #endregion

    #region Change Password 
    [HttpPost("users/{userId:guid}/password/rotate")]
    public async Task<ActionResult<AuthenticationResultDto>> RotatePasswordAfter90Days(
        Guid userId,
        ChangePasswordRequest request)
    {
        try
        {
            var result = await _mediator.Send(new ChangePasswordCommand(
                userId,
                request.CurrentPassword,
                request.NewPassword));

            return Ok(result);
        }
        catch (InvalidOperationException ex) when (ex.Message.Equals("User not found.", StringComparison.Ordinal))
        {
            return NotFound();
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }
    #endregion

    #region Forgot Password
    [HttpPost("forgot-password")]
    public async Task<ActionResult<ForgotPasswordTokenDto>> ForgotPassword(ForgotPasswordRequest request)
    {
        var result = await _mediator.Send(new ForgotPasswordCommand(request.Email));
        return Ok(result);
    }
    #endregion
}
