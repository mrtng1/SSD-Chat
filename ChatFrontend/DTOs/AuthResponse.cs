namespace ChatFrontend.DTOs;

public record AuthResponse
{
    public string Token { get; set; }
    public string RefreshToken { get; set; }
    public string PublicKey { get; set; }
}