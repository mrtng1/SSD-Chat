using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ChatServer.Models
{
    public class Message
    {
        [Key]
        public Guid PrimaryKey { get; set; }
    }
}
