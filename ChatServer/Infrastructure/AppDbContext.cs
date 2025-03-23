using ChatServer.Models;
using Microsoft.EntityFrameworkCore;

namespace ChatServer.Infrastructure
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options)
            : base(options) { }

        public DbSet<User> Users => Set<User>();
        public DbSet<Message> Messages => Set<Message>();
    }
}
