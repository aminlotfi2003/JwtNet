using FluentValidation;

namespace Application.Users.Dtos.Signup;

public record SignupRequest(string Username, string Email, string Password, string PasswordConfirm);

public class SignupRequestValidator : AbstractValidator<SignupRequest>
{
    public SignupRequestValidator()
    {
        // Validate that Name is required and not empty
        RuleFor(signup => signup.Username)
            .NotEmpty().WithMessage("Name is required.");

        // Validate that Email is required and is in a valid email format
        RuleFor(signup => signup.Email)
            .NotEmpty().WithMessage("Email is required.")
            .EmailAddress().WithMessage("A valid email address is required.");

        // Validate that Password is required and meets minimum length requirements
        RuleFor(signup => signup.Password)
            .NotEmpty().WithMessage("Password is required.")
            .MinimumLength(6).WithMessage("Password must be at least 6 characters long.");

        // Validate that PasswordHash matches Password
        RuleFor(signup => signup.PasswordConfirm)
            .NotEmpty().WithMessage("Password confirmation is required.")
            .Equal(signup => signup.Password).WithMessage("Passwords do not match.");
    }
}
