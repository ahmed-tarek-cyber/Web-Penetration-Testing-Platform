using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace WebScanner.Models
{
    public class SourceCodeReviewReport
    {
        [Key]
        public string Id { get; set; } = Guid.NewGuid().ToString();

        [Required]
        public int UserId { get; set; }

        [Required]
        public string FileName { get; set; } = string.Empty;

        [Required]
        public string OriginalFileName { get; set; } = string.Empty;

        [Required]
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public DateTime? CompletedAt { get; set; }

        [Required, MaxLength(50)]
        public string Status { get; set; } = "Success";

        [Required, MaxLength(50)]
        public string OverallStatus { get; set; } = "Safe";

        [Required]
        public int TotalFindings { get; set; } = 0;

        [Required]
        public long FileSize { get; set; } = 0;

        [Required, MaxLength(100)]
        public string Engine { get; set; } = "SphinxEye-Core v2";

        // JSON string containing findings for storage
        [Required]
        public string FindingsJson { get; set; } = "[]";

        // JSON string containing severity breakdown
        [Required]
        public string SeverityBreakdownJson { get; set; } = "{}";

        // Navigation property
        [JsonIgnore]
        public User? User { get; set; }
    }
}
