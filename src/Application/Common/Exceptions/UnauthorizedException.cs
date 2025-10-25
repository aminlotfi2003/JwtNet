using System.Net;

namespace Application.Common.Exceptions;

public sealed class UnauthorizedException : HttpException
{
    public UnauthorizedException(string message)
        : base(HttpStatusCode.Unauthorized, message)
    {
    }
}
