namespace ChatFrontend.DTOs;

public record RegisterRequest
{
    public string Username { get; set; }
    public string Password { get; set; }
    public string PublicKey { get; set; }
}