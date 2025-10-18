using API.Contracts.Identity;
using Application.Identity.Commands.ChangePassword;
using Application.Identity.Commands.ExternalLogin;
using Application.Identity.Commands.ForgotPassword;
using Application.Identity.Commands.LoginUser;
using Application.Identity.Commands.LogoutUser;
using Application.Identity.Commands.RefreshToken;
using Application.Identity.Commands.RegisterUser;
using Application.Identity.Commands.TwoFactor.EnableEmailTwoFactor;
using Application.Identity.Commands.TwoFactor.GenerateEmailTwoFactorToken;
using Application.Identity.Commands.TwoFactor.VerifyTwoFactorLogin;
using Application.Identity.DTOs;
using Application.Identity.Queries.GetUserLoginHistory;
using Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers.v1;

[ApiController]
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/identity")]
public sealed class IdentityController : ControllerBase
{
    private readonly IMediator _mediator;
    private readonly SignInManager<ApplicationUser> _signInManager;

    public IdentityController(
        IMediator mediator,
        SignInManager<ApplicationUser> signInManager)
    {
        _mediator = mediator;
        _signInManager = signInManager;
    }

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
    public async Task<ActionResult<LoginResultDto>> Login(LoginUserRequest request)
    {
        try
        {
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            var userAgent = Request.Headers.UserAgent.ToString();

            var result = await _mediator.Send(new LoginUserCommand(
                request.Email,
                request.Password,
                ipAddress,
                userAgent));
            return Ok(result);
        }
        catch (InvalidOperationException ex)
        {
            return Unauthorized(new { message = ex.Message });
        }
    }

    [HttpPost("login/two-factor")]
    public async Task<ActionResult<AuthenticationResultDto>> VerifyTwoFactorLogin(VerifyTwoFactorLoginRequest request)
    {
        try
        {
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            var userAgent = Request.Headers.UserAgent.ToString();

            var result = await _mediator.Send(new VerifyTwoFactorLoginCommand(
                request.UserId,
                request.TwoFactorCode,
                ipAddress,
                userAgent));

            return Ok(result);
        }
        catch (InvalidOperationException ex)
        {
            return Unauthorized(new { message = ex.Message });
        }
    }
    #endregion

    #region External Login
    [HttpGet("external/{provider}/challenge")]
    public IActionResult ChallengeExternalLogin(string provider, [FromQuery] string? returnUrl = null)
    {
        var callbackUrl = Url.Action(
            nameof(ExternalLoginCallback),
            new { provider, returnUrl });

        if (string.IsNullOrWhiteSpace(callbackUrl))
            return BadRequest(new { message = "Unable to determine callback URL." });

        var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, callbackUrl);
        return Challenge(properties, provider);
    }

    [HttpGet("external/{provider}/callback")]
    public async Task<ActionResult<AuthenticationResultDto>> ExternalLoginCallback(string provider)
    {
        try
        {
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            var userAgent = Request.Headers.UserAgent.ToString();

            var result = await _mediator.Send(new ExternalLoginCommand(
                provider,
                ipAddress,
                userAgent));

            return Ok(result);
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { message = ex.Message });
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

    #region Two-Factor Authentication
    [HttpPost("users/{userId:guid}/two-factor/email/generate")]
    public async Task<ActionResult<TwoFactorTokenDto>> GenerateEmailTwoFactorToken(Guid userId)
    {
        try
        {
            var token = await _mediator.Send(new GenerateEmailTwoFactorTokenCommand(userId));
            return Ok(token);
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpPost("users/{userId:guid}/two-factor/email/enable")]
    public async Task<IActionResult> EnableEmailTwoFactor(Guid userId, EnableEmailTwoFactorRequest request)
    {
        try
        {
            await _mediator.Send(new EnableEmailTwoFactorCommand(userId, request.TwoFactorCode));
            return NoContent();
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }
    #endregion

    #region Login History
    [HttpGet("users/{userId:guid}/login-history")]
    public async Task<ActionResult<IReadOnlyCollection<UserLoginHistoryDto>>> GetLoginHistory(
        Guid userId,
        [FromQuery] int count = 10)
    {
        var histories = await _mediator.Send(new GetUserLoginHistoryQuery(userId, count));
        return Ok(histories);
    }
    #endregion
}
