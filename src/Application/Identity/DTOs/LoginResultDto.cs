namespace Application.Identity.DTOs;

public sealed record LoginResultDto(
    bool RequiresTwoFactor,
    Guid? UserId,
    string? TwoFactorProvider,
    string? TwoFactorToken,
    AuthenticationResultDto? AuthenticationResult
)
{
    public static LoginResultDto Success(AuthenticationResultDto authenticationResult) =>
        new(false, null, null, null, authenticationResult);

    public static LoginResultDto RequiresTwoFactorResponse(Guid userId, string twoFactorProvider, string twoFactorToken) =>
        new(true, userId, twoFactorProvider, twoFactorToken, null);
}
