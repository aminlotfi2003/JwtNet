using System.Net;

namespace Application.Common.Exceptions;

public sealed class BadRequestException : HttpException
{
    public BadRequestException(string message)
        : base(HttpStatusCode.BadRequest, message)
    {
    }
}
