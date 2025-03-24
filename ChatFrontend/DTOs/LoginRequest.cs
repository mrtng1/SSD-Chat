namespace ChatFrontend.DTOs;

public record LoginRequest
{
    public string Username { get; set; }
    public string Password { get; set; }
}