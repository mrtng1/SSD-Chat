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

    public async Task<string> EncryptAsync(string message, string ivBase64)
    {
        return await _jsRuntime.InvokeAsync<string>(
            "encryptMessage",
            message,
            SharedSecrets.AesKeyBase64,
            ivBase64
        );
    }

    public async Task<string> DecryptAsync(string encryptedBase64, string ivBase64)
    {
        return await _jsRuntime.InvokeAsync<string>(
            "decryptMessage",
            encryptedBase64,
            SharedSecrets.AesKeyBase64,
            ivBase64
        );
    }
    
    public string GenerateRandomAesIv()
    {
        byte[] iv = new byte[12];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(iv);
        }
        return Convert.ToBase64String(iv);
    }
    
}