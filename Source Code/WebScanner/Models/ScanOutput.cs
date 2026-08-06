using System;
using System.Collections.Generic;

namespace WebScanner.Models
{
    public class ScanOutput
    {
        public string ReportId { get; set; } = "";
        public string Url { get; set; } = "";
        public string Status { get; set; } = "";
        public string AiSummary { get; set; } = "";
        public DateTime? CompletedAt { get; set; }
        public bool HasInputs { get; set; }
        public double Duration { get; set; }

        public List<ScanIssue> Issues { get; set; } = new();
    }

    public class ScanIssue
    {
        public string Name { get; set; } = "";
        public string Description { get; set; } = "";
        public string Severity { get; set; } = "";
        public string Color { get; set; } = "";
        public string Location { get; set; } = "";
        public string Parameter { get; set; } = "";
        public string Payload { get; set; } = "";

        // *********** New Python + Universal scanner fields ***********

        public string? ScannerName { get; set; }
        public string? Evidence { get; set; }
        public string? Method { get; set; }
        public string? Path { get; set; }
        public string? Source { get; set; }
    }
}
