using Application.Extensions.DependencyInjection;
using Infrastructure.Extensions.DependencyInjection;

namespace API.Extensions.DependencyInjection;

public static class SeviceCollectionExtensions
{
    public static IServiceCollection AddServices(this IServiceCollection services, IConfiguration configuration)
    {
        // Register Dependencies Layers
        services.AddApplication()
                .AddInfrastructure(configuration);

        // Register API Versioning
        services.AddApiVersioningDependencies();

        // Register Swagger
        services.AddSwaggerWithJwtAuth(
            title: "JwtNet API",
            version: "v1",
            description: "JwtNet API documentation"
        );

        // Register Services
        services.AddAuthentication();
        services.AddHttpContextAccessor();

        return services;
    }
}
