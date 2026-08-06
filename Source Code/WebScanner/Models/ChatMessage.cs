using Microsoft.EntityFrameworkCore.Metadata.Internal;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace WebScanner.Models
{
    public class ChatMessage
    {
        [Key]
        public int Id { get; set; }

        [ForeignKey("ChatSession")]
        public int ChatSessionId { get; set; }
        [JsonIgnore]
        public ChatSession ChatSession { get; set; }

        public string Role { get; set; } // "user" | "assistant"

        public string Content { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.Now;


    }
}
