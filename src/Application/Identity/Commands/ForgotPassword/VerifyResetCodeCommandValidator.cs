using FluentValidation;

namespace Application.Identity.Commands.ForgotPassword;

public sealed class VerifyResetCodeCommandValidator : AbstractValidator<VerifyResetCodeCommand>
{
    public VerifyResetCodeCommandValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty()
            .EmailAddress();

        RuleFor(x => x.VerificationCode)
            .NotEmpty()
            .Length(6)
            .Matches("^\\d{6}$")
            .WithMessage("Verification code must be a 6-digit number.");
    }
}
