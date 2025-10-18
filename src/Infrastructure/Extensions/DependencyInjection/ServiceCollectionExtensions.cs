using Application.Abstractions.Repositories;
using Application.Abstractions.Services;
using Application.Identity.Options;
using Domain.Entities;
using Infrastructure.Contexts;
using Infrastructure.Repositories;
using Infrastructure.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace Infrastructure.Extensions.DependencyInjection;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        // Register DbContext
        services.AddDbContext<JwtNetDbContext>(options =>
            options.UseSqlServer(configuration.GetConnectionString("Default")));

        services.Configure<JwtOptions>(configuration.GetSection(JwtOptions.SectionName));

        services.AddIdentityCore<ApplicationUser>(options =>
        {
            options.User.RequireUniqueEmail = true;
            options.Password.RequireDigit = true;
            options.Password.RequireLowercase = true;
            options.Password.RequireUppercase = true;
            options.Password.RequireNonAlphanumeric = false;
            options.Password.RequiredLength = 8;
            options.Lockout.AllowedForNewUsers = true;
            options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);
            options.Lockout.MaxFailedAccessAttempts = 3;
        })
            .AddRoles<IdentityRole<Guid>>()
            .AddEntityFrameworkStores<JwtNetDbContext>()
            .AddSignInManager()
            .AddDefaultTokenProviders();

        var jwtOptions = new JwtOptions();
        configuration.GetSection(JwtOptions.SectionName).Bind(jwtOptions);

        var authenticationBuilder = services
            .AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddCookie(IdentityConstants.ExternalScheme, options =>
            {
                options.Cookie.Name = "JwtNet.External";
                options.ExpireTimeSpan = TimeSpan.FromMinutes(5);
            })
            .AddJwtBearer(options =>
            {
                options.RequireHttpsMetadata = false;
                options.SaveToken = true;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.SigningKey)),
                    ValidateIssuer = true,
                    ValidIssuer = jwtOptions.Issuer,
                    ValidateAudience = true,
                    ValidAudience = jwtOptions.Audience,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                };
            });

        ConfigureGoogle(authenticationBuilder, configuration);
        ConfigureMicrosoft(authenticationBuilder, configuration);
        ConfigureGitHub(authenticationBuilder, configuration);

        // Register Services
        services.AddScoped<IDateTimeProvider, SystemDateTimeProvider>();
        services.AddScoped<ITokenService, TokenService>();
        services.AddScoped<IAuthenticationResultService, AuthenticationResultService>();

        // Register Repositories
        services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
        services.AddScoped<IUserPasswordHistoryRepository, UserPasswordHistoryRepository>();
        services.AddScoped<IUserLoginHistoryRepository, UserLoginHistoryRepository>();

        return services;
    }

    private static void ConfigureGoogle(AuthenticationBuilder builder, IConfiguration configuration)
    {
        var section = configuration.GetSection("Authentication:Google");
        var clientId = section["ClientId"];
        var clientSecret = section["ClientSecret"];

        if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(clientSecret))
            return;

        builder.AddGoogle(options =>
        {
            options.ClientId = clientId;
            options.ClientSecret = clientSecret;
            options.SaveTokens = true;
            options.Scope.Add("email");
            options.Scope.Add("profile");
        });
    }

    private static void ConfigureMicrosoft(AuthenticationBuilder builder, IConfiguration configuration)
    {
        var section = configuration.GetSection("Authentication:Microsoft");
        var clientId = section["ClientId"];
        var clientSecret = section["ClientSecret"];

        if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(clientSecret))
            return;

        builder.AddMicrosoftAccount(options =>
        {
            options.ClientId = clientId;
            options.ClientSecret = clientSecret;
            options.SaveTokens = true;
            options.Scope.Add("email");
            options.Scope.Add("profile");
        });
    }

    private static void ConfigureGitHub(AuthenticationBuilder builder, IConfiguration configuration)
    {
        var section = configuration.GetSection("Authentication:GitHub");
        var clientId = section["ClientId"];
        var clientSecret = section["ClientSecret"];

        if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(clientSecret))
            return;

        builder.AddGitHub(options =>
        {
            options.ClientId = clientId;
            options.ClientSecret = clientSecret;
            options.SaveTokens = true;
            options.Scope.Add("user:email");
        });
    }
}
