using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace WebScanner.Models
{
    public class ChatSession
    {
        [Key]
        public int Id { get; set; }
        public int UserId { get; set; } // المستخدم
        public DateTime CreatedAt { get; set; } = DateTime.Now;
        public string? ScanReportId { get; set; }
        public string? SourceCodeReviewReportId { get; set; }
        [ForeignKey("SourceCodeReviewReportId")]
        public virtual SourceCodeReviewReport? SourceCodeReviewReport { get; set; }
        [ForeignKey("ScanReportId")]
        [JsonIgnore]
        public virtual ScanReport? ScanReport { get; set; }
        public virtual  List<ChatMessage> Messages { get; set; }
    }
}
