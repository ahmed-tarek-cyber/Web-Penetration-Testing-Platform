using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization; 

namespace WebScanner.Models
{
    public class ScanReport
    {
        [Key]
        public string Id { get; set; } = Guid.NewGuid().ToString();

        [Required, Url]
        public string Url { get; set; } = string.Empty;

        [Required, MaxLength(32)]
        public string Status { get; set; } = "Pending";

        [Required]
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public DateTime? CompletedAt { get; set; }

        public double ScanDurationSeconds
        {
            get
            {
                if (CompletedAt == null) return 0;
                return (CompletedAt.Value - CreatedAt).TotalSeconds;
            }
        }

        public bool HasInputs { get; set; } = false;

        public string AiSummary { get; set; } = string.Empty;

        public List<Vulnerability> Results { get; set; } = new();

      
        public int UserId { get; set; }

        // خاصية اختيارية للتنقل (Navigation Property)
        [JsonIgnore]
        public User? User { get; set; }
    }
}