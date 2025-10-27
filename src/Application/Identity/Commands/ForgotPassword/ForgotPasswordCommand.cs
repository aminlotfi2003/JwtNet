using Application.Identity.DTOs;
using MediatR;

namespace Application.Identity.Commands.ForgotPassword;

public sealed record ForgotPasswordCommand(string Email, string? IpAddress, string? TenantId) : IRequest<ForgotPasswordTokenDto>;
