using System.Security.Cryptography;
using Microsoft.JSInterop;

namespace ChatFrontend.Services;

public class EncryptionService
{
    private readonly IJSRuntime _jsRuntime;

    public EncryptionService(IJSRuntime jsRuntime)
    {
        _jsRuntime = jsRuntime;
    }

    public async Task<string> EncryptAsync(string message, string ivBase64, string recipientPublicKey, string senderPublicKey)
    {
        string encryptionKey = DeriveEncryptionKey(recipientPublicKey, senderPublicKey);
        return await _jsRuntime.InvokeAsync<string>(
            "encryptMessage",
            message,
            encryptionKey,
            ivBase64
        );
    }

    public async Task<string> DecryptAsync(string encryptedBase64, string ivBase64, string recipientPublicKey, string senderPublicKey)
    {
        string encryptionKey = DeriveEncryptionKey(recipientPublicKey, senderPublicKey);
        return await _jsRuntime.InvokeAsync<string>(
            "decryptMessage",
            encryptedBase64,
            encryptionKey,
            ivBase64
        );
    }
    
    // Generate a random initialization vector to decode messages
    public string GenerateRandomAesIv()
    {
        byte[] iv = new byte[12];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(iv);
        }
        return Convert.ToBase64String(iv);
    }
    
    // Derive a message encryption key from both users public keys
    private static string DeriveEncryptionKey(string user1PublicKey, string user2PublicKey)
    {
        string combinedKeys = user1PublicKey + user2PublicKey;
        
        using (var sha256 = System.Security.Cryptography.SHA256.Create())
        {
            byte[] hash = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(combinedKeys));
            string derivedKey = Convert.ToBase64String(hash);
            return derivedKey;
        }
    }


    
    
}