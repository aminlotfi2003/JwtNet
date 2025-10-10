namespace Application.Users.Dtos.Login;

public record LoginResponse(bool Flag, string Message = null!, string Token = null!);
