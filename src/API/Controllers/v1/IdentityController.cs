using API.Contracts.Identity;
using Application.Identity.Commands.ChangePassword;
using Application.Identity.Commands.ForgotPassword;
using Application.Identity.Commands.LoginUser;
using Application.Identity.Commands.LogoutUser;
using Application.Identity.Commands.RefreshToken;
using Application.Identity.Commands.RegisterUser;
using Application.Identity.Commands.ResetPassword;
using Application.Identity.Commands.TwoFactor.EnableEmailTwoFactor;
using Application.Identity.Commands.TwoFactor.GenerateEmailTwoFactorToken;
using Application.Identity.Commands.TwoFactor.VerifyTwoFactorLogin;
using Application.Identity.DTOs;
using Application.Identity.Queries.GetUserLoginHistory;
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
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        var tenantId = Request.Headers.TryGetValue("X-Tenant-Id", out var tenantValues) ? tenantValues.ToString() : null;
        var asn = Request.Headers.TryGetValue("X-ASN", out var asnValues) ? asnValues.ToString() : null;
        var result = await _mediator.Send(new RegisterUserCommand(
            request.Email,
            request.Password,
            request.ConfirmPassword,
            request.FirstName,
            request.LastName,
            request.Gender,
            request.BirthDate,
            ipAddress,
            asn,
            tenantId)
        );

        return Ok(result);
    }
    #endregion

    #region Login
    [HttpPost("login")]
    public async Task<ActionResult<LoginResultDto>> Login(LoginUserRequest request)
    {
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        var userAgent = Request.Headers.UserAgent.ToString();
        var deviceId = Request.Headers.TryGetValue("X-Device-Id", out var deviceValues)
            ? deviceValues.ToString()
            : userAgent;
        var isHighRisk = Request.Headers.TryGetValue("X-High-Risk", out var riskValues)
            && bool.TryParse(riskValues.ToString(), out var risk) && risk;
        var result = await _mediator.Send(new LoginUserCommand(
            request.Email,
            request.Password,
            ipAddress,
            userAgent,
            deviceId,
            isHighRisk)
        );
        return Ok(result);
    }

    [HttpPost("login/two-factor")]
    public async Task<ActionResult<AuthenticationResultDto>> VerifyTwoFactorLogin(VerifyTwoFactorLoginRequest request)
    {
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        var userAgent = Request.Headers.UserAgent.ToString();
        var challengeId = Request.Headers.TryGetValue("X-2FA-Challenge-Id", out var challengeValues)
            ? challengeValues.ToString()
            : null;
        var result = await _mediator.Send(new VerifyTwoFactorLoginCommand(
            request.UserId,
            request.TwoFactorCode,
            ipAddress,
            userAgent,
            challengeId)
        );

        return Ok(result);
    }
    #endregion

    #region Refresh
    [HttpPost("refresh")]
    public async Task<ActionResult<AuthenticationResultDto>> Refresh(RefreshTokenRequest request)
    {
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        var clientId = Request.Headers.TryGetValue("X-Client-Id", out var clientValues) ? clientValues.ToString() : null;
        var result = await _mediator.Send(new RefreshTokenCommand(request.RefreshToken, ipAddress, clientId));
        return Ok(result);
    }
    #endregion

    #region Logout
    [HttpPost("logout")]
    public async Task<IActionResult> Logout(LogoutUserRequest request)
    {
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        await _mediator.Send(new LogoutUserCommand(request.RefreshToken, ipAddress));
        return NoContent();
    }
    #endregion

    #region Change Password
    [HttpPost("users/{userId:guid}/password/rotate")]
    public async Task<ActionResult<AuthenticationResultDto>> RotatePasswordAfter90Days(
        Guid userId,
        ChangePasswordRequest request)
    {
        var result = await _mediator.Send(new ChangePasswordCommand(
            userId,
            request.CurrentPassword,
            request.NewPassword,
            HttpContext.Connection.RemoteIpAddress?.ToString())
        );

        return Ok(result);
    }
    #endregion

    #region Forgot Password
    [HttpPost("forgot-password")]
    public async Task<ActionResult<ForgotPasswordTokenDto>> ForgotPassword(ForgotPasswordRequest request)
    {
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        var tenantId = Request.Headers.TryGetValue("X-Tenant-Id", out var tenantValues) ? tenantValues.ToString() : null;
        var result = await _mediator.Send(new ForgotPasswordCommand(request.Email, ipAddress, tenantId));
        return Ok(result);
    }
    #endregion

    #region Verify Reset Code
    [HttpPost("forgot-password/verify")]
    public async Task<ActionResult<PasswordResetCodeVerificationResultDto>> VerifyResetCode(VerifyResetCodeRequest request)
    {
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        var result = await _mediator.Send(new VerifyResetCodeCommand(request.Email, request.VerificationCode, ipAddress));
        return Ok(result);
    }
    #endregion

    #region Reset Password
    [HttpPost("reset-password")]
    public async Task<ActionResult<PasswordResetResultDto>> ResetPassword(ResetPasswordRequest request)
    {
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        var result = await _mediator.Send(new ResetPasswordCommand(
            request.Email,
            request.ResetToken,
            request.VerificationCode,
            request.NewPassword,
            request.ConfirmPassword,
            ipAddress)
        );

        return Ok(result);
    }
    #endregion

    #region Two-Factor Authentication
    [HttpPost("users/{userId:guid}/two-factor/email/generate")]
    public async Task<ActionResult<TwoFactorTokenDto>> GenerateEmailTwoFactorToken(Guid userId)
    {
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        var token = await _mediator.Send(new GenerateEmailTwoFactorTokenCommand(userId, ipAddress));
        return Ok(token);
    }

    [HttpPost("users/{userId:guid}/two-factor/email/enable")]
    public async Task<IActionResult> EnableEmailTwoFactor(Guid userId, EnableEmailTwoFactorRequest request)
    {
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        await _mediator.Send(new EnableEmailTwoFactorCommand(userId, request.TwoFactorCode, ipAddress));
        return NoContent();
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
