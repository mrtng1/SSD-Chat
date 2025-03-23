using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ChatServer.Models
{
    [Index(nameof(Username), IsUnique = true)]
    [Table("Users")]
    public class User
    {
        [Key]
        public Guid PrimaryKey { get; set; } = Guid.NewGuid();
        [Required, MaxLength(50)]
        public string Username { get; set; } = null!;

        [Required]
        public byte[] PasswordHash { get; set; } = null!;

        [Required]
        public byte[] PasswordSalt { get; set; } = null!;

        [Required]
        public byte[] PublicKey { get; set; } = null!;

        public string? ConnectionId { get; set; } 
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime LastLogin { get; set; }
        public string? RefreshToken { get; set; }
        public DateTime? RefreshTokenExpiry { get; set; }
    }
}
