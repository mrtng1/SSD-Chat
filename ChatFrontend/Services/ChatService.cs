using ChatServer.DTOs;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.SignalR.Client;

namespace ChatFrontend.Services;

public class ChatService
{
    private HubConnection? _hubConnection;
    private readonly AuthenticationStateProvider _authenticationStateProvider;
    
    public ChatService(AuthenticationStateProvider authenticationStateProvider)
    {
        _authenticationStateProvider = authenticationStateProvider;
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
        await _hubConnection.InvokeAsync("SendPrivateMessage", message);
    }
    

    public void OnMessageReceived(Action<Message> handler)
    {
        _hubConnection.On("ReceiveMessage", handler);
    }
}