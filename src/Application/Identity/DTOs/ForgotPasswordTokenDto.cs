namespace Application.Identity.DTOs;

public sealed record ForgotPasswordTokenDto(
    bool Success,
    string Message,
    string? ResetToken,
    string? VerificationCode)
{
    public static ForgotPasswordTokenDto SuccessWithToken(string token, string message, string verificationCode) =>
        new(true, message, token, verificationCode);

    public static ForgotPasswordTokenDto SuccessWithoutToken(string message) => new(true, message, null, null);
}
