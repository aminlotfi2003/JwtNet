using System.Net;

namespace Application.Common.Exceptions;

public abstract class HttpException : Exception
{
    protected HttpException(HttpStatusCode statusCode, string message)
        : base(message)
    {
        StatusCode = statusCode;
    }

    public HttpStatusCode StatusCode { get; }
}
