namespace API.Contracts.Identity;

public sealed class VerifyResetCodeRequest
{
    public string Email { get; set; } = string.Empty;
    public string VerificationCode { get; set; } = string.Empty;
}
