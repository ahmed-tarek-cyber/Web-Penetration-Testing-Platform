namespace WebScanner.Models
{
    public class ChatRequest
    {
         
        public int ChatId { get; set; }// معرف الجلسة (اختياري، إذا كان موجود يعني استمرارية الجلسة)
        public string? ScanReportId { get; set; } // 🆕 ضيف السطر ده هنا
        public string? SourceCodeReviewReportId { get; set; }
        public string? Message { get; set; }
        public string? AiPromptContext { get; set; }
    }
}
