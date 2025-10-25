using Application.Common.Exceptions;
using MediatR;
using System.Text.RegularExpressions;

namespace Application.Common.Behaviors;

public sealed class XssGuardPipelineBehavior<TRequest, TResponse>
    : IPipelineBehavior<TRequest, TResponse>
    where TRequest : notnull
{
    private static readonly Regex DangerousContentPattern = new(
        "(<script\\b|javascript:|on\\w+\\s*=)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public async Task<TResponse> Handle(
        TRequest request,
        RequestHandlerDelegate<TResponse> next,
        CancellationToken cancellationToken)
    {
        var stringProperties = request
            .GetType()
            .GetProperties()
            .Where(property => property.PropertyType == typeof(string));

        foreach (var property in stringProperties)
        {
            var value = property.GetValue(request) as string;
            if (string.IsNullOrWhiteSpace(value))
                continue;

            if (DangerousContentPattern.IsMatch(value))
                throw new BadRequestException("Request contains potentially malicious script content.");
        }

        return await next();
    }
}
