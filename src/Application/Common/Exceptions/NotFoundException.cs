using System.Net;

namespace Application.Common.Exceptions;

public sealed class NotFoundException : HttpException
{
    public NotFoundException(string message)
        : base(HttpStatusCode.NotFound, message)
    {
    }
}
