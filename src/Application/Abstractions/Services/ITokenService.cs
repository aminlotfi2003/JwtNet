using Application.Identity.Models;
using Domain.Entities;

namespace Application.Abstractions.Services;

public interface ITokenService
{
    TokenPair GenerateTokenPair(ApplicationUser user);
    string ComputeHash(string value);
}
