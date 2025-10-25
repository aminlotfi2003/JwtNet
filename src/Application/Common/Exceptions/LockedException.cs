using System.Net;

namespace Application.Common.Exceptions;

public sealed class LockedException : HttpException
{
    public LockedException(string message)
        : base(HttpStatusCode.Locked, message)
    {
    }
}
