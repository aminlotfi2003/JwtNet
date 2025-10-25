using System.Net.Http.Json;
using System.Text.Json;

var baseAddress = args.Length > 0 ? args[0] : "https://localhost:5104";

Console.ForegroundColor = ConsoleColor.Cyan;
Console.WriteLine("Forgot Password Tester");
Console.ResetColor();
Console.WriteLine($"Using API base address: {baseAddress}");
Console.Write("Enter the email address to test: ");
var email = Console.ReadLine();

if (string.IsNullOrWhiteSpace(email))
{
    Console.WriteLine("Email is required.");
    return;
}

using var httpClientHandler = new HttpClientHandler
{
    ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
};

using var httpClient = new HttpClient(httpClientHandler)
{
    BaseAddress = new Uri(baseAddress)
};

var serializerOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web);

Console.WriteLine();
Console.WriteLine("Requesting password reset token...");

var forgotResponse = await httpClient.PostAsJsonAsync(
    "api/v1/identity/forgot-password",
    new { Email = email });

if (!forgotResponse.IsSuccessStatusCode)
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine($"Request failed with status code {forgotResponse.StatusCode}.");
    Console.ResetColor();
    return;
}

var forgotPayload = await forgotResponse.Content.ReadFromJsonAsync<ForgotPasswordResponse>(serializerOptions);
if (forgotPayload is null)
{
    Console.WriteLine("Unable to parse response.");
    return;
}

Console.WriteLine();
Console.WriteLine(forgotPayload.Message);
Console.WriteLine($"Verification Code (for testing): {forgotPayload.VerificationCode ?? "<none>"}");
Console.WriteLine($"Reset Token: {forgotPayload.ResetToken ?? "<none>"}");

Console.WriteLine();
Console.Write("Enter the verification code to validate it: ");
var verificationCode = Console.ReadLine();

if (string.IsNullOrWhiteSpace(verificationCode))
{
    Console.WriteLine("Verification code is required to proceed.");
    return;
}

var verifyResponse = await httpClient.PostAsJsonAsync(
    "api/v1/identity/forgot-password/verify",
    new { Email = email, VerificationCode = verificationCode });

if (!verifyResponse.IsSuccessStatusCode)
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine($"Verification failed with status code {verifyResponse.StatusCode}.");
    Console.ResetColor();
    return;
}

var verifyPayload = await verifyResponse.Content.ReadFromJsonAsync<VerificationResponse>(serializerOptions);
if (verifyPayload is null)
{
    Console.WriteLine("Unable to parse verification response.");
    return;
}

Console.WriteLine(verifyPayload.Message);

if (!string.IsNullOrEmpty(forgotPayload.ResetToken))
{
    Console.WriteLine();
    Console.Write("Would you like to test resetting the password now? (y/N): ");
    var answer = Console.ReadLine();

    if (string.Equals(answer, "y", StringComparison.OrdinalIgnoreCase))
    {
        Console.Write("Enter the new password: ");
        var newPassword = Console.ReadLine();

        Console.Write("Confirm the new password: ");
        var confirmPassword = Console.ReadLine();

        var resetResponse = await httpClient.PostAsJsonAsync(
            "api/v1/identity/reset-password",
            new
            {
                Email = email,
                ResetToken = forgotPayload.ResetToken,
                VerificationCode = verificationCode,
                NewPassword = newPassword,
                ConfirmPassword = confirmPassword
            });

        if (!resetResponse.IsSuccessStatusCode)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Reset failed with status code {resetResponse.StatusCode}.");
            Console.ResetColor();
            return;
        }

        var resetPayload = await resetResponse.Content.ReadFromJsonAsync<ResetPasswordResponse>(serializerOptions);
        if (resetPayload is null)
        {
            Console.WriteLine("Unable to parse reset response.");
            return;
        }

        Console.WriteLine(resetPayload.Message);
    }
}

Console.WriteLine();
Console.ForegroundColor = ConsoleColor.Green;
Console.WriteLine("Test scenario complete.");
Console.ResetColor();

internal sealed record ForgotPasswordResponse(bool Success, string Message, string? ResetToken, string? VerificationCode);

internal sealed record VerificationResponse(bool Success, string Message);

internal sealed record ResetPasswordResponse(bool Success, string Message);