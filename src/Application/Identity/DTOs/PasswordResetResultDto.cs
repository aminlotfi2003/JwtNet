namespace Application.Identity.DTOs;

public sealed record PasswordResetResultDto(bool Success, string Message)
{
    public static PasswordResetResultDto SuccessResult(string message) => new(true, message);

    public static PasswordResetResultDto FailureResult(string message) => new(false, message);
}
