using ChatServer.DTOs;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.SignalR.Client;

namespace ChatFrontend.Services;

public class ChatService
{
    private HubConnection? _hubConnection;
    private readonly AuthenticationStateProvider _authenticationStateProvider;
    private readonly EncryptionService _encryptionService;

    
    public ChatService(AuthenticationStateProvider authenticationStateProvider, EncryptionService encryptionService)
    {
        _authenticationStateProvider = authenticationStateProvider;
        _encryptionService = encryptionService;
    }

    public async Task InitializeAsync()
    {
        var authState = await _authenticationStateProvider.GetAuthenticationStateAsync();
        var jwtToken = authState.User.FindFirst("JWT")?.Value;
        
        if (string.IsNullOrEmpty(jwtToken))
        {
            throw new InvalidOperationException("JWT token is missing or invalid.");
        }

        _hubConnection = new HubConnectionBuilder()
            .WithUrl("http://localhost:5065/chathub", options => 
            {
                options.AccessTokenProvider = () => Task.FromResult(jwtToken);
            })
            .Build();

        await _hubConnection.StartAsync();
    }

    public async Task SendMessage(Message message)
    {
        string encryptedMessage = await _encryptionService.EncryptAsync(
            message.Content,
            SharedSecrets.AesKeyBase64,
            SharedSecrets.AesIvBase64
        );

        message.Content = encryptedMessage;
        
        await _hubConnection.InvokeAsync("SendPrivateMessage", message);
    }
    

    public void OnMessageReceived(Action<Message> handler)
    {
        _hubConnection.On<Message>("ReceiveEncryptedMessage", async (encryptedMessage) =>
        {
            string decryptedContent = await _encryptionService.DecryptAsync(
                encryptedMessage.Content, 
                SharedSecrets.AesKeyBase64,
                SharedSecrets.AesIvBase64
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
}