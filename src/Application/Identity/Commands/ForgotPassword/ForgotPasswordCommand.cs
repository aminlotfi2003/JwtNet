using Application.Identity.DTOs;
using MediatR;

namespace Application.Identity.Commands.ForgotPassword;

public sealed record ForgotPasswordCommand(string Email) : IRequest<ForgotPasswordTokenDto>;
