using Application.Abstractions.Services;
using System.Collections.Immutable;

namespace Infrastructure.Services;

internal sealed class DisposableEmailDomainService : IDisposableEmailDomainService
{
    private static readonly ImmutableHashSet<string> DisposableDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "mailinator.com",
        "tempmail.com",
        "10minutemail.com",
        "guerrillamail.com",
        "yopmail.com",
        "trashmail.com"
    }.ToImmutableHashSet(StringComparer.OrdinalIgnoreCase);

    public bool IsDisposable(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return false;
        }

        if (DisposableDomains.Contains(domain))
        {
            return true;
        }

        return domain.EndsWith(".mailinator.com", StringComparison.OrdinalIgnoreCase)
               || domain.EndsWith(".tempmail.com", StringComparison.OrdinalIgnoreCase)
               || domain.EndsWith(".yopmail.com", StringComparison.OrdinalIgnoreCase);
    }
}
