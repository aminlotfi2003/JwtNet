namespace Application.Identity.DTOs;

public sealed record ForgotPasswordTokenDto(bool Success, string? ResetToken)
{
    public static ForgotPasswordTokenDto SuccessWithToken(string token) => new(true, token);

    public static ForgotPasswordTokenDto SuccessWithoutToken() => new(true, null);
}
