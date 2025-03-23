using ChatServer.Infrastructure;
using ChatServer.Models;
using Microsoft.AspNetCore.SignalR;

namespace ChatServer.Service
{
    public class ChatHub : Hub
    {
        private readonly AppDbContext _context;

        public ChatHub(AppDbContext context)
        {
            _context = context;
        }

        // Register user with their public key
        public async Task RegisterUser(string username, byte[] publicKey)
        {
            var user = _context.Users
                .FirstOrDefault(u => u.Username == username);

            if (user == null)
            {
                user = new User { Username = username, PublicKey = publicKey };
                _context.Users.Add(user);
            }
            else
            {
                user.PublicKey = publicKey;
            }

            user.ConnectionId = Context.ConnectionId;
            _context.SaveChanges();
        }

        // Get public key for a user
        public async Task<byte[]> GetPublicKey(string username)
        {
            var user =  _context.Users
                .FirstOrDefault(u => u.Username == username);

            return user?.PublicKey ?? Array.Empty<byte>();
        }

        // Relay encrypted message to recipient
        public async Task SendEncryptedMessage(string recipientUsername, byte[] encryptedData)
        {
            var recipient =  _context.Users
                .FirstOrDefault(u => u.Username == recipientUsername);

            if (recipient?.ConnectionId == null) return;

            Clients.Client(recipient.ConnectionId).SendAsync("ReceiveEncryptedMessage", encryptedData);
        }

        // Cleanup on disconnect
        public override async Task OnDisconnectedAsync(Exception? exception)
        {
            var user = _context.Users
                .FirstOrDefault(u => u.ConnectionId == Context.ConnectionId);

            if (user != null)
            {
                user.ConnectionId = null;
                await _context.SaveChangesAsync();
            }

            await base.OnDisconnectedAsync(exception);
        }
    }
}
