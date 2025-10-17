namespace API.Contracts.Identity;

public sealed record VerifyTwoFactorLoginRequest(Guid UserId, string TwoFactorCode);
