using Application.Users.Dtos.Login;
using Application.Users.Dtos.Signup;

namespace Application.Abstractions.Services;

public interface IAuthService
{
    Task<SignupResponse> Signup(SignupRequest signup);
    Task<LoginResponse> Login(LoginRequest login);
}
