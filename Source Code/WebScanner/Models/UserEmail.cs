using System;
using System.ComponentModel.DataAnnotations;

namespace WebScanner.Models
{
    public class UserEmail
    {
        public int Id { get; set; }

        [Required, EmailAddress, MaxLength(320)]
        public string Email { get; set; } = string.Empty;

        // Login / Register / Unknown
        [Required, MaxLength(32)]
        public string Source { get; set; } = "Unknown";

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }
}
