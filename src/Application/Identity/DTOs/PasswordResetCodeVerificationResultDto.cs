namespace Application.Identity.DTOs;

public sealed record PasswordResetCodeVerificationResultDto(bool Success, string Message)
{
    public static PasswordResetCodeVerificationResultDto SuccessResult(string message) => new(true, message);

    public static PasswordResetCodeVerificationResultDto FailureResult(string message) => new(false, message);
}
