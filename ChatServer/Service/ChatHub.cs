using ChatServer.DTOs;
using ChatServer.Infrastructure;
using ChatServer.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;
using Message = ChatServer.DTOs.Message;

namespace ChatServer.Service
{
    [Authorize]
    public class ChatHub : Hub
    {
        
        public async Task SendPrivateMessage(Message message)
        {
            // This will send the message to all connections that belong to the given user identifier.
            Console.WriteLine($"Sending private message to user: {message.Recipient}");
            await Clients.User(message.Recipient).SendAsync("ReceiveMessage", message);
        }
        
        public override async Task OnConnectedAsync()
        {
            var connectionId = Context.ConnectionId;
            var userId = Context.UserIdentifier;
            Console.WriteLine($"New connection: ConnectionId = {connectionId}, UserIdentifier = {userId}");

            if (!string.IsNullOrEmpty(userId))
            {
                await Groups.AddToGroupAsync(connectionId, userId);
                Console.WriteLine($"Added connection {connectionId} to group {userId}.");
            }
            else
            {
                Console.WriteLine("No UserIdentifier found, so no group assignment was done.");
            }

            await base.OnConnectedAsync();
        }


        public override async Task OnDisconnectedAsync(Exception? exception)
        {
            // Remove the connection from your tracking collection
            await base.OnDisconnectedAsync(exception);
        }

    }
}
