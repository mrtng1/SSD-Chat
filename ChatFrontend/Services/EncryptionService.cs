using System.Security.Cryptography;
using System.Text;
using Microsoft.JSInterop;

namespace ChatFrontend.Services;

public static class SharedSecrets
{
    public static readonly string AesKeyBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes("1234567890abcdef"));
}

public class EncryptionService
{
    private readonly IJSRuntime _jsRuntime;

    public EncryptionService(IJSRuntime jsRuntime)
    {
        _jsRuntime = jsRuntime;
    }

    public async Task<string> EncryptAsync(string message, string keyBase64, string ivBase64)
    {
        return await _jsRuntime.InvokeAsync<string>(
            "encryptMessage",
            message,
            keyBase64,
            ivBase64
        );
    }

    public async Task<string> DecryptAsync(string encryptedBase64, string keyBase64, string ivBase64)
    {
        return await _jsRuntime.InvokeAsync<string>(
            "decryptMessage",
            encryptedBase64,
            keyBase64,
            ivBase64
        );
    }
    
    public string GenerateRandomAesIv()
    {
        byte[] iv = new byte[12]; // 12 bytes = 96 bits (required for AES-GCM)
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(iv);
        }
        return Convert.ToBase64String(iv); // Now matches GCM's IV size
    }
}