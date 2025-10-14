namespace API.Contracts.Identity;

public sealed record ChangePasswordRequest(string CurrentPassword, string NewPassword);
