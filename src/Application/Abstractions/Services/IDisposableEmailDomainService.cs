namespace Application.Abstractions.Services;

public interface IDisposableEmailDomainService
{
    bool IsDisposable(string domain);
}
