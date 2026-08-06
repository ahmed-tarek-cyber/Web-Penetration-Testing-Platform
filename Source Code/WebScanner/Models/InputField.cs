using System;
using System.ComponentModel.DataAnnotations;

namespace WebScanner.Models
{
    public class InputField
    {
        [Key]
        public Guid Id { get; set; }   
        [Required]
        public string Name { get; set; } = string.Empty;

        [Required]
        public string Type { get; set; } = string.Empty;

        public string Value { get; set; } = string.Empty;
    }
}
