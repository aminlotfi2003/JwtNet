using Application.Abstractions.Services;
using Application.Users.Dtos.Login;
using Application.Users.Dtos.Signup;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers.v1;

[ApiController]
[Route("api/v1/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _svc;

    public AuthController(IAuthService svc) => _svc = svc;

    [HttpPost("Login")]
    public async Task<ActionResult<LoginResponse>> Login(LoginRequest login)
    {
        var result = await _svc.Login(login);
        return Ok(result);
    }

    [HttpPost("Signup")]
    public async Task<ActionResult<SignupResponse>> Signup(SignupRequest signup)
    {
        var result = await _svc.Signup(signup);
        return Ok(result);
    }
}
