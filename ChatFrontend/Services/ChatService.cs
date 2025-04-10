using System.Security.Cryptography;
using Blazored.LocalStorage;
using ChatServer.DTOs;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.JSInterop;

namespace ChatFrontend.Services;

public class ChatService
{
    private HubConnection? _hubConnection;
    private readonly AuthenticationStateProvider _authenticationStateProvider;
    private readonly ILocalStorageService _localStorage;
    private readonly IJSRuntime _jsRuntime;
    private readonly Dictionary<string, object> _sharedSecrets = new();
    private object? _localPrivateKey;

    
    public ChatService(AuthenticationStateProvider authenticationStateProvider, ILocalStorageService localStorage,
        IJSRuntime jsRuntime)
    {
        _authenticationStateProvider = authenticationStateProvider;
        _localStorage = localStorage;
        _jsRuntime = jsRuntime;
    }

    public async Task InitializeAsync()
    {
        var authState = await _authenticationStateProvider.GetAuthenticationStateAsync();
        var jwtToken = authState.User.FindFirst("JWT")?.Value;
        
        if (string.IsNullOrEmpty(jwtToken))
            throw new InvalidOperationException("JWT token is missing");

        // Initialize SignalR
        _hubConnection = new HubConnectionBuilder()
            .WithUrl("http://localhost:5065/chathub", options => 
                options.AccessTokenProvider = () => Task.FromResult(jwtToken))
            .Build();

        await _hubConnection.StartAsync();

        // Load private key
        var storedKey = await _localStorage.GetItemAsync<string>("ecdh_private");
        _localPrivateKey = await _jsRuntime.InvokeAsync<object>(
            "importPrivateKey", 
            storedKey
        );
    }

    public async Task SendMessage(Message message)
    {
        var sharedSecret = await GetOrCreateSharedSecret(message.RecipientPublicKey);
        string messageIv = GenerateRandomAesIv();
        
        string encryptedMessage = await _jsRuntime.InvokeAsync<string>(
            "encryptMessage",
            message.Content,
            sharedSecret,
            messageIv
        );

        message.Content = encryptedMessage;
        message.EncryptionIv = messageIv;
        
        await _hubConnection.InvokeAsync("SendPrivateMessage", message);
    }
    

    public void OnMessageReceived(Action<Message> handler)
    {
        _hubConnection.On<Message>("ReceiveEncryptedMessage", async (encryptedMessage) =>
        {
            
            var sharedSecret = await GetOrCreateSharedSecret(encryptedMessage.SenderPublicKey);
            
            string decryptedContent = await _jsRuntime.InvokeAsync<string>(
                "decryptMessage",
                encryptedMessage.Content,
                sharedSecret,
                encryptedMessage.EncryptionIv
            );
            
            Message decryptedMessage = new Message
            {
                Content = decryptedContent,     
                Sender = encryptedMessage.Sender,
                SenderName = encryptedMessage.SenderName,
                Recipient = encryptedMessage.Recipient
            };

            handler(decryptedMessage);
        });
        
    }
    
    private async Task<object> GetOrCreateSharedSecret(string publicKey)
    {
        // Get Shared Secret
        if (_sharedSecrets.TryGetValue(publicKey, out var secret))
            return secret;
    
        // Create Shared Secret
        var storedKey = await _localStorage.GetItemAsync<string>("ecdh_private");
        var newSecret = await _jsRuntime.InvokeAsync<object>(
            "deriveSharedSecret",
            publicKey,
            storedKey
        );
    
        _sharedSecrets[publicKey] = newSecret;
        return newSecret;
    }

    public void Dispose()
    {
        _hubConnection?.DisposeAsync();
        _sharedSecrets.Clear();
    }
    
    private string GenerateRandomAesIv()
    {
        byte[] iv = new byte[12];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(iv);
        }
        return Convert.ToBase64String(iv);
    }
    
}