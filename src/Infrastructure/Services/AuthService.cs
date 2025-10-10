using Application.Abstractions.Services;
using Application.Users.Dtos.Login;
using Application.Users.Dtos.Signup;
using Domain.Entities;
using Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Infrastructure.Services;

public class AuthService : IAuthService
{
    private readonly AppDbContext _context;
    private readonly IConfiguration _configuration;

    public AuthService(AppDbContext context, IConfiguration configuration)
    {
        _context = context; _configuration = configuration;
    }

    private async Task<ApplicationUser> FindUserByEmail(string email) => await _context.Users.FirstOrDefaultAsync(u => u.Email == email);

    private string GenerateJwtToken(ApplicationUser user)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:key"]));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        var userClaims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.UserName),
            new Claim(ClaimTypes.Email, user.Email),
        };

        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            claims: userClaims,
            expires: DateTime.Now.AddDays(1),
            signingCredentials: credentials
            );
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public async Task<LoginResponse> Login(LoginRequest login)
    {
        var email = await FindUserByEmail(login.Email);
        if (email == null)
            return new LoginResponse(false, "User Not Found.");

        bool checkPassword = BCrypt.Net.BCrypt.Verify(login.Password, email.PasswordHash);
        if (checkPassword)
            return new LoginResponse(true, "Login Succeeded.", GenerateJwtToken(email));
        else
            return new LoginResponse(false, "Login Failed");
    }

    public async Task<SignupResponse> Signup(SignupRequest signup)
    {
        var email = await FindUserByEmail(signup.Email);
        //if (email == null)
        //    return new SignupResponse(false, "User Already Exists.");

        _context.Users.Add(new ApplicationUser()
        {
            UserName = signup.Username,
            Email = signup.Email,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(signup.Password)
        });
        await _context.SaveChangesAsync();
        return new SignupResponse(true, "Signup Completed.");
    }
}
