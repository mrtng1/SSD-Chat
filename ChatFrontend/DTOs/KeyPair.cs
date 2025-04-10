using System.Text.Json.Serialization;

namespace ChatFrontend.DTOs;

public class KeyPair
{
    public string PublicKey { get; set; }
    public Jwk PrivateKey { get; set; }
}

public class Jwk
{
    [JsonPropertyName("kty")]
    public string KeyType { get; set; }
    
    [JsonPropertyName("crv")]
    public string Curve { get; set; }
    
    [JsonPropertyName("x")]
    public string X { get; set; }
    
    [JsonPropertyName("y")]
    public string Y { get; set; }
    
    [JsonPropertyName("d")]
    public string D { get; set; }
}