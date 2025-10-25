using System.Net;

namespace Application.Common.Exceptions;

public sealed class ConflictException : HttpException
{
    public ConflictException(string message)
        : base(HttpStatusCode.Conflict, message)
    {
    }
}
