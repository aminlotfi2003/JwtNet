using Microsoft.AspNetCore.Mvc;

namespace API.Extensions;

public static class ApiVersioningExtensions
{
    public static IServiceCollection AddApiVersioningDependencies(this IServiceCollection services)
    {
        services.AddApiVersioning(options =>
        {
            options.DefaultApiVersion = new ApiVersion(1, 0);
            options.AssumeDefaultVersionWhenUnspecified = true;
            options.ReportApiVersions = true;
            options.ApiVersionReader = new Microsoft.AspNetCore.Mvc.Versioning.UrlSegmentApiVersionReader();
        });

        return services;
    }
}
