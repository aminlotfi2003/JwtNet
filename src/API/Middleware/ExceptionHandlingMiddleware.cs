using Application.Common.Exceptions;
using FluentValidation;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using System.Globalization;
using System.Net;

namespace API.Middleware;

public sealed class ExceptionHandlingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ExceptionHandlingMiddleware> _logger;

    public ExceptionHandlingMiddleware(RequestDelegate next, ILogger<ExceptionHandlingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (ValidationException ex)
        {
            _logger.LogWarning(ex, "Validation failure detected for request {Path}", context.Request.Path);
            await WriteValidationProblemAsync(context, ex);
        }
        catch (HttpException ex)
        {
            _logger.LogWarning(ex, "Request {Path} failed with status code {StatusCode}", context.Request.Path, ex.StatusCode);
            if (ex is RateLimitException rateLimit)
            {
                AppendRateLimitHeaders(context.Response, rateLimit);
            }
            await WriteProblemAsync(context, ex.StatusCode, ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unhandled exception occurred while processing request {Path}", context.Request.Path);
            await WriteProblemAsync(
                context,
                StatusCodes.Status500InternalServerError,
                "An unexpected error occurred. Please try again later.",
                "An unexpected error occurred.");
        }
    }

    private static Task WriteProblemAsync(HttpContext context, HttpStatusCode statusCode, string detail, string? title = null)
    {
        return WriteProblemAsync(context, (int)statusCode, detail, title);
    }

    private static async Task WriteProblemAsync(HttpContext context, int statusCode, string detail, string? title = null)
    {
        context.Response.ContentType = "application/json";
        context.Response.StatusCode = statusCode;

        var problem = new ProblemDetails
        {
            Status = statusCode,
            Title = title ?? ReasonPhrases.GetReasonPhrase(statusCode),
            Detail = detail,
            Instance = context.Request.Path
        };

        await context.Response.WriteAsJsonAsync(problem);
    }

    private static async Task WriteValidationProblemAsync(HttpContext context, ValidationException exception)
    {
        context.Response.ContentType = "application/json";
        context.Response.StatusCode = StatusCodes.Status400BadRequest;

        var errors = exception.Errors
            .GroupBy(error => error.PropertyName)
            .ToDictionary(
                grouping => grouping.Key,
                grouping => grouping
                    .Select(error => error.ErrorMessage)
                    .Distinct()
                    .ToArray());

        var problem = new ValidationProblemDetails(errors)
        {
            Status = StatusCodes.Status400BadRequest,
            Title = "One or more validation errors occurred.",
            Instance = context.Request.Path
        };

        await context.Response.WriteAsJsonAsync(problem);
    }

    private static void AppendRateLimitHeaders(HttpResponse response, RateLimitException exception)
    {
        if (exception.RetryAfter is { } retryAfter)
        {
            var seconds = Math.Max(0, (int)Math.Ceiling(retryAfter.TotalSeconds));
            response.Headers.RetryAfter = seconds.ToString(CultureInfo.InvariantCulture);
        }

        response.Headers["X-RateLimit-Action"] = exception.Action.ToString();

        if (exception.LockDuration is { } lockDuration)
        {
            var seconds = Math.Max(0, (int)Math.Ceiling(lockDuration.TotalSeconds));
            response.Headers["X-RateLimit-Lock"] = seconds.ToString(CultureInfo.InvariantCulture);
        }
    }
}
