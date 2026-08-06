using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;
using WebScanner.Models;

namespace WebScanner.Services
{
    /// <summary>
    /// AI helper service that summarizes and explains scan reports.
    /// If an OpenAI API key is available, it calls the Chat Completions API.
    /// Otherwise, it generates a local heuristic summary.
    /// </summary>
    public class AiScannerService
    {
        private readonly HttpClient _http;
        private readonly string? _openAiKey;

        // 🔸 helper to treat “Safe” items specially
        private static bool IsSafeItem(Vulnerability v) =>
            v != null && v.Name != null &&
            v.Name.Equals("Safe", StringComparison.OrdinalIgnoreCase);

        public AiScannerService(HttpClient http)
        {
            _http = http ?? throw new ArgumentNullException(nameof(http));
            _openAiKey = Environment.GetEnvironmentVariable("OPENAI_API_KEY");
        }

        public async Task<string> AnalyzeReportAsync(ScanReport report)
        {
            if (report == null)
                return "Invalid report (null).";

            // ⭐ NEW: Handle Unknown (no inputs detected)
            // استخدام (report.Status ?? "") لتجنب خطأ null
            if ((report.Status ?? "").Equals("Unknown", StringComparison.OrdinalIgnoreCase))
            {
                return $"ℹ️ Scan completed, but no testable inputs were detected.\n" +
                       $"The target URL '{report.Url}' does not contain query parameters or form fields.\n" +
                       $"Consider scanning a URL that accepts user input to perform a deeper security analysis.";
            }

            var results = report.Results ?? new List<Vulnerability>();

            // ignore “Safe” entries when counting
            var findings = results.Where(v => !IsSafeItem(v)).ToList();

            // ✅ الحل هنا: استخدام (v.Severity ?? "") لمنع الـ null reference
            int countHigh = findings.Count(v => (v.Severity ?? "").Equals("High", StringComparison.OrdinalIgnoreCase));
            int countMedium = findings.Count(v => (v.Severity ?? "").Equals("Medium", StringComparison.OrdinalIgnoreCase));
            int countInfo = findings.Count(v => (v.Severity ?? "").Equals("Info", StringComparison.OrdinalIgnoreCase));
            int total = findings.Count;

            // ------------------------
            // 🔥 OPENAI MODE
            // ------------------------
            if (!string.IsNullOrWhiteSpace(_openAiKey))
            {
                try
                {
                    string prompt = BuildPrompt(report, findings, countHigh, countMedium, countInfo, total);

                    var reqObj = new
                    {
                        model = "gpt-4o-mini-2024-08-06",
                        messages = new[]
                        {
                            new { role = "system", content = "You are a professional cybersecurity analyst that summarizes vulnerability scan reports clearly and concisely." },
                            new { role = "user", content = prompt }
                        },
                        max_tokens = 500
                    };

                    string json = JsonSerializer.Serialize(reqObj);
                    using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.openai.com/v1/chat/completions");
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _openAiKey);
                    request.Content = new StringContent(json, Encoding.UTF8, "application/json");

                    using var response = await _http.SendAsync(request);
                    string body = await response.Content.ReadAsStringAsync();

                    if (response.IsSuccessStatusCode)
                    {
                        try
                        {
                            using var doc = JsonDocument.Parse(body);
                            if (doc.RootElement.TryGetProperty("choices", out var choices) && choices.GetArrayLength() > 0)
                            {
                                var msg = choices[0].GetProperty("message").GetProperty("content").GetString();
                                return msg ?? "No textual analysis returned.";
                            }
                        }
                        catch (JsonException)
                        {
                            return $"AI response could not be parsed: {body}";
                        }
                    }

                    return $"AI analysis failed: {response.StatusCode} - {body}";
                }
                catch (Exception ex)
                {
                    return $"AI analysis error: {ex.Message}";
                }
            }

            // ------------------------
            // 📌 LOCAL FALLBACK MODE
            // ------------------------
            var sb = new StringBuilder();
            sb.AppendLine($"🧭 Target: {report.Url}");
            sb.AppendLine($"🔖 Status: {report.Status}");
            sb.AppendLine($"📊 Counts — High: {countHigh}, Medium: {countMedium}, Info: {countInfo}, Total: {total}");
            sb.AppendLine(new string('-', 40));

            // Safe case
            if ((report.Status ?? "").Equals("Safe", StringComparison.OrdinalIgnoreCase) || total == 0)
            {
                sb.AppendLine("✅ No vulnerabilities detected in this scan.");
                return sb.ToString();
            }

            // list findings by severity priority
            void writeGroup(string title, string sev)
            {
                var group = findings
                    // ✅ الحل هنا أيضاً: معالجة الـ null في التصفية
                    .Where(v => (v.Severity ?? "").Equals(sev, StringComparison.OrdinalIgnoreCase))
                    .GroupBy(v => (Name: v.Name ?? sev, Desc: v.Description ?? $"Detected indicator of {v.Name ?? sev}."))
                    .Select(g => g.First());

                if (group.Any())
                {
                    sb.AppendLine(title);
                    foreach (var v in group)
                    {
                        var desc = string.IsNullOrWhiteSpace(v.Description)
                            ? $"Detected indicator of {v.Name}."
                            : v.Description;
                        sb.AppendLine($"• {v.Name} — {desc}");
                    }
                    sb.AppendLine();
                }
            }

            writeGroup("🚨 High severity:", "High");
            writeGroup("⚠️ Medium severity:", "Medium");
            writeGroup("ℹ️ Informational:", "Info");

            sb.AppendLine("✅ Recommendations:");
            if (countHigh > 0) sb.AppendLine("- Immediately fix High issues (e.g., SQLi/LFI) and add WAF rules where possible.");
            if (countMedium > 0) sb.AppendLine("- Sanitize/encode all user inputs and outputs to prevent XSS.");
            sb.AppendLine("- Use parameterized queries and least-privilege DB accounts.");
            sb.AppendLine("- Keep dependencies and runtime patched.");

            return sb.ToString();
        }

        // Prompt builder for OpenAI
        private static string BuildPrompt(ScanReport report, List<Vulnerability> findings,
                                          int countHigh, int countMedium, int countInfo, int total)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"Target URL: {report.Url}");
            sb.AppendLine($"Overall Status: {report.Status}");
            sb.AppendLine($"Counts — High: {countHigh}, Medium: {countMedium}, Info: {countInfo}, Total: {total}");
            sb.AppendLine();
            sb.AppendLine("Detected findings (exclude any 'Safe' entries):");
            sb.AppendLine("-------------------");

            if (findings != null && findings.Count > 0)
            {
                foreach (var r in findings)
                {
                    var desc = string.IsNullOrWhiteSpace(r.Description)
                        ? $"Detected indicator of {r.Name}."
                        : r.Description;

                    sb.AppendLine($"Name: {r.Name}");
                    sb.AppendLine($"Severity: {r.Severity}");
                    sb.AppendLine($"Description: {desc}");
                    sb.AppendLine();
                }
            }
            else
            {
                sb.AppendLine("No findings (non-safe) to list.");
            }

            sb.AppendLine("If Overall Status is 'Safe', state that no vulnerabilities were detected and avoid speculative risks.");
            sb.AppendLine("Summarize the results and provide 2–3 high-impact, actionable mitigation recommendations.");
            return sb.ToString();
        }
    }
}