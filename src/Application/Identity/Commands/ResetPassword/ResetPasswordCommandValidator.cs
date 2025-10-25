using FluentValidation;

namespace Application.Identity.Commands.ResetPassword;

public sealed class ResetPasswordCommandValidator : AbstractValidator<ResetPasswordCommand>
{
    public ResetPasswordCommandValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty()
            .EmailAddress();

        RuleFor(x => x.ResetToken)
            .NotEmpty();

        RuleFor(x => x.VerificationCode)
            .NotEmpty()
            .Length(6)
            .Matches("^\\d{6}$")
            .WithMessage("Verification code must be a 6-digit number.");

        RuleFor(x => x.NewPassword)
            .NotEmpty()
            .MinimumLength(8);

        RuleFor(x => x.ConfirmPassword)
            .Equal(x => x.NewPassword)
            .WithMessage("Confirmation password must match the new password.");
    }
}
