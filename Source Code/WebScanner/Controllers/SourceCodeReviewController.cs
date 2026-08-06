using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Globalization;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using WebScanner.Data;
using WebScanner.Models;
using Microsoft.EntityFrameworkCore;

namespace WebScanner.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/source-code-review")]
    public class SourceCodeReviewController : ControllerBase
    {
        private const long MaxUploadSize = 5 * 1024 * 1024;
        private const int ScanTimeoutSeconds = 45;
        private readonly AppDbContext _db;

        public SourceCodeReviewController(AppDbContext db)
        {
            _db = db;
        }

        private static readonly HashSet<string> AllowedExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".js", ".html", ".htm"
        };

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNamingPolicy = null,
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        [HttpPost("scan")]
        [RequestSizeLimit(MaxUploadSize + 1024 * 128)]
        [Consumes("multipart/form-data")]
        public async Task<IActionResult> Scan(IFormFile file, CancellationToken cancellationToken)
        {
            if (file == null || file.Length == 0)
                return BadRequest(new { error = "File is required" });

            var extension = Path.GetExtension(file.FileName);
            if (string.IsNullOrWhiteSpace(extension) || !AllowedExtensions.Contains(extension))
                return BadRequest(new { error = "Only .js, .html, and .htm files are supported" });

            if (file.Length > MaxUploadSize)
                return BadRequest(new { error = "File exceeds maximum allowed size" });

            var userId = GetCurrentUserId();
            var reportId = Guid.NewGuid().ToString("N");
            var originalFileName = Path.GetFileName(file.FileName);
            var safeFileStem = MakeSafeFileStem(originalFileName);

            var scannersDir = Path.Combine(AppContext.BaseDirectory, "Scanners");
            var scriptPath = Path.Combine(scannersDir, "source_code_review_scanner.py");

            if (!System.IO.File.Exists(scriptPath))
                return StatusCode(StatusCodes.Status500InternalServerError, new { error = $"Scanner script not found: {scriptPath}" });

            var tempFile = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid()}{extension}");
            await using (var stream = System.IO.File.Create(tempFile))
            {
                await file.CopyToAsync(stream, cancellationToken);
            }

            try
            {
                SourceCodeReviewScannerReportDto? scannerReport;

                try
                {
                    scannerReport = await RunScannerAsync(scriptPath, scannersDir, tempFile, cancellationToken);
                }
                catch (TimeoutException)
                {
                    return StatusCode(StatusCodes.Status408RequestTimeout, new { error = "Scan timeout exceeded" });
                }
                catch (Exception ex)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, new { error = ex.Message });
                }

                if (scannerReport == null)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, new { error = "Scanner returned no output" });
                }

                NormalizeReportForDisplay(scannerReport, originalFileName);

                var createdAt = DateTime.UtcNow;
                var completedAt = DateTime.UtcNow;
                var reportFolder = EnsureReportFolder(userId);
                var jsonPath = Path.Combine(reportFolder, $"{reportId}.json");
                var htmlPath = Path.Combine(reportFolder, $"{reportId}.html");

                var storedReport = new StoredSourceCodeReviewReport
                {
                    ReportId = reportId,
                    UserId = userId,
                    OriginalFileName = originalFileName,
                    FileName = originalFileName,
                    CreatedAt = createdAt,
                    CompletedAt = completedAt,
                    HtmlFileName = Path.GetFileName(htmlPath),
                    JsonFileName = Path.GetFileName(jsonPath),
                    Engine = scannerReport.Engine ?? "SphinxEye-Core v2",
                    Status = scannerReport.Status ?? "success",
                    FileSize = scannerReport.FileSize,
                    OverallStatus = scannerReport.OverallStatus ?? "Safe",
                    TotalFindings = scannerReport.TotalFindings,
                    SeverityBreakdown = scannerReport.SeverityBreakdown ?? new Dictionary<string, int>(),
                    Findings = scannerReport.Findings ?? new List<SourceCodeReviewFindingDto>()
                };

                await System.IO.File.WriteAllTextAsync(jsonPath, JsonSerializer.Serialize(storedReport, JsonOptions), cancellationToken);
                await System.IO.File.WriteAllTextAsync(htmlPath, BuildHtmlReport(storedReport), cancellationToken);

                // Save to database
                var dbReport = new SourceCodeReviewReport
                {
                    Id = reportId,
                    UserId = userId,
                    FileName = originalFileName,
                    OriginalFileName = originalFileName,
                    CreatedAt = createdAt,
                    CompletedAt = completedAt,
                    Status = storedReport.Status ?? "success",
                    OverallStatus = storedReport.OverallStatus ?? "Safe",
                    TotalFindings = storedReport.TotalFindings,
                    FileSize = storedReport.FileSize,
                    Engine = storedReport.Engine ?? "SphinxEye-Core v2",
                    FindingsJson = JsonSerializer.Serialize(storedReport.Findings ?? new(), JsonOptions),
                    SeverityBreakdownJson = JsonSerializer.Serialize(storedReport.SeverityBreakdown ?? new Dictionary<string, int>(), JsonOptions)
                };

                _db.SourceCodeReviewReports.Add(dbReport);
                await _db.SaveChangesAsync(cancellationToken);

                return Ok(new
                {
                    reportId = storedReport.ReportId,
                    fileName = storedReport.FileName,
                    createdAt = storedReport.CreatedAt,
                    completedAt = storedReport.CompletedAt,
                    engine = storedReport.Engine,
                    status = storedReport.Status,
                    file_size = storedReport.FileSize,
                    overall_status = storedReport.OverallStatus,
                    total_findings = storedReport.TotalFindings,
                    severity_breakdown = storedReport.SeverityBreakdown,
                    findings = storedReport.Findings,
                    downloadUrl = GetDownloadUrl(storedReport.ReportId)
                });
            }
            finally
            {
                try { System.IO.File.Delete(tempFile); } catch { }
            }
        }

        [HttpGet("reports")]
        public async Task<IActionResult> ListReports()
        {
            var userId = GetCurrentUserId();
            
            var dbReports = await _db.SourceCodeReviewReports
                .Where(r => r.UserId == userId)
                .OrderByDescending(r => r.CreatedAt)
                .ToListAsync();

            var reports = dbReports.Select(r => new
            {
                reportId = r.Id,
                fileName = r.FileName,
                createdAt = r.CreatedAt,
                completedAt = r.CompletedAt,
                status = r.Status,
                overallStatus = r.OverallStatus,
                totalFindings = r.TotalFindings,
                severityBreakdown = JsonSerializer.Deserialize<Dictionary<string, int>>(r.SeverityBreakdownJson) ?? new(),
                downloadUrl = GetDownloadUrl(r.Id)
            })
            .ToList();

            return Ok(reports);
        }

        [HttpGet("reports/{reportId}/download")]
        public async Task<IActionResult> DownloadReport(string reportId)
        {
            var userId = GetCurrentUserId();
            var dbReport = await _db.SourceCodeReviewReports.FirstOrDefaultAsync(r => r.Id == reportId && r.UserId == userId);
            
            if (dbReport == null)
                return NotFound(new { error = "Report not found or access denied" });

            var storedReport = LoadReportById(reportId);
            if (storedReport == null)
                return NotFound(new { error = "Report not found or access denied" });

            var reportFolder = EnsureReportFolder(storedReport.UserId);
            var htmlPath = Path.Combine(reportFolder, storedReport.HtmlFileName);
            if (!System.IO.File.Exists(htmlPath))
                return NotFound(new { error = "HTML report file not found" });

            var bytes = System.IO.File.ReadAllBytes(htmlPath);
            var fileName = $"SphinxEye_Source_Review_{MakeSafeFileStem(storedReport.OriginalFileName)}_{storedReport.CreatedAt:yyyyMMdd_HHmm}.html";
            return File(bytes, "text/html", fileName);
        }

        [HttpDelete("reports/{reportId}")]
        public async Task<IActionResult> DeleteReport(string reportId)
        {
            var storedReport = LoadReportById(reportId);
            if (storedReport == null)
                return NotFound(new { error = "Report not found or access denied" });

            // Delete from database
            var dbReport = await _db.SourceCodeReviewReports.FirstOrDefaultAsync(r => r.Id == reportId && r.UserId == GetCurrentUserId());
            if (dbReport != null)
            {
                _db.SourceCodeReviewReports.Remove(dbReport);
                await _db.SaveChangesAsync();
            }

            // Delete from file system (fallback for existing reports)
            var reportFolder = EnsureReportFolder(storedReport.UserId);
            TryDeleteFile(Path.Combine(reportFolder, storedReport.JsonFileName));
            TryDeleteFile(Path.Combine(reportFolder, storedReport.HtmlFileName));

            return Ok(new { message = "Report deleted successfully" });
        }

        private async Task<SourceCodeReviewScannerReportDto?> RunScannerAsync(string scriptPath, string workingDirectory, string tempFile, CancellationToken cancellationToken)
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "python",
                Arguments = $"\"{scriptPath}\" \"{tempFile}\"",
                WorkingDirectory = workingDirectory,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };

            using var process = new Process { StartInfo = startInfo };
            process.Start();

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(ScanTimeoutSeconds));

            try
            {
                await process.WaitForExitAsync(timeout.Token);
            }
            catch (OperationCanceledException)
            {
                try { if (!process.HasExited) process.Kill(true); } catch { }
                throw new TimeoutException("Scan timeout exceeded");
            }

            var stdout = await process.StandardOutput.ReadToEndAsync();
            var stderr = await process.StandardError.ReadToEndAsync();

            if (process.ExitCode != 0)
                throw new InvalidOperationException(string.IsNullOrWhiteSpace(stdout) ? stderr : stdout);

            if (string.IsNullOrWhiteSpace(stdout))
                return null;

            return JsonSerializer.Deserialize<SourceCodeReviewScannerReportDto>(stdout, JsonOptions);
        }

        private void NormalizeReportForDisplay(SourceCodeReviewScannerReportDto report, string originalFileName)
        {
            report.File = originalFileName;

            if (report.Findings == null)
                return;

            foreach (var finding in report.Findings)
            {
                finding.File = originalFileName;
            }
        }

        private string BuildHtmlReport(StoredSourceCodeReviewReport report)
        {
            var findings = report.Findings ?? new List<SourceCodeReviewFindingDto>();
            var counts = report.SeverityBreakdown ?? new Dictionary<string, int>();
            var critical = GetSeverityCount(counts, "Critical");
            var high = GetSeverityCount(counts, "High");
            var medium = GetSeverityCount(counts, "Medium");
            var low = GetSeverityCount(counts, "Low");
            var info = GetSeverityCount(counts, "Info");

            var sb = new StringBuilder();
            sb.Append($@"<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Source Code Review Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0b0f14; color: #eef2f7; margin: 0; padding: 24px; }}
        .container {{ max-width: 1100px; margin: 0 auto; background: #0f141b; border: 1px solid rgba(255,255,255,0.08); border-radius: 24px; padding: 32px; box-shadow: 0 30px 60px rgba(0,0,0,0.35); }}
        h1, h2 {{ margin: 0 0 14px 0; }}
        h1 {{ color: #ff3b3b; font-size: 34px; }}
        .meta {{ color: #9aa3b2; margin: 4px 0; }}
        .summary {{ display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 14px; margin: 24px 0; }}
        .stat {{ background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.08); border-radius: 18px; padding: 16px; }}
        .stat strong {{ display: block; font-size: 28px; margin-top: 8px; }}
        .critical {{ color: #ff4d4f; }}
        .high {{ color: #ff8f3d; }}
        .medium {{ color: #ffd166; }}
        .low {{ color: #2ec4b6; }}
        .info {{ color: #9aa0a6; }}
        .finding {{ margin: 16px 0; border-radius: 18px; overflow: hidden; border: 1px solid rgba(255,255,255,0.08); background: rgba(255,255,255,0.03); }}
        .finding-head {{ display:flex; justify-content:space-between; gap: 12px; align-items:center; padding: 16px 18px; border-left: 5px solid #ffd166; }}
        .finding-head.critical {{ border-left-color: #ff4d4f; }}
        .finding-head.high {{ border-left-color: #ff8f3d; }}
        .finding-head.medium {{ border-left-color: #ffd166; }}
        .finding-head.low {{ border-left-color: #2ec4b6; }}
        .finding-head.info {{ border-left-color: #9aa0a6; }}
        .finding-title {{ font-size: 18px; font-weight: 700; }}
        .severity-pill {{ padding: 6px 12px; border-radius: 999px; font-size: 12px; font-weight: 700; background: rgba(255,255,255,0.08); }}
        .finding-body {{ padding: 16px 18px 18px; }}
        .row {{ margin: 10px 0; }}
        .label {{ color: #9aa3b2; font-weight: 600; display:block; margin-bottom: 4px; }}
        .value, pre {{ background: rgba(0,0,0,0.28); border: 1px solid rgba(255,255,255,0.06); border-radius: 12px; padding: 12px; white-space: pre-wrap; word-break: break-word; overflow-wrap: anywhere; margin: 0; color: #e7eaf0; }}
        .footer {{ margin-top: 26px; color: #8b94a7; font-size: 12px; text-align:center; }}
    </style>
</head>
<body>
    <div class='container'>
        <h1>Source Code Review Report</h1>
        <p class='meta'>File: {HtmlEncode(report.OriginalFileName)}</p>
        <p class='meta'>Scan Date: {report.CreatedAt.ToLocalTime():yyyy-MM-dd HH:mm:ss}</p>
        <p class='meta'>Overall Status: {HtmlEncode(report.OverallStatus)}</p>

        <div class='summary'>
            <div class='stat'><span>Critical</span><strong class='critical'>{critical}</strong></div>
            <div class='stat'><span>High</span><strong class='high'>{high}</strong></div>
            <div class='stat'><span>Medium</span><strong class='medium'>{medium}</strong></div>
            <div class='stat'><span>Low</span><strong class='low'>{low}</strong></div>
            <div class='stat'><span>Info</span><strong class='info'>{info}</strong></div>
        </div>

        <h2>Findings</h2>");

            if (!findings.Any())
            {
                sb.Append("<p>No findings detected.</p>");
            }
            else
            {
                foreach (var finding in findings)
                {
                    var severity = (finding.Severity ?? "Info").Trim();
                    var severityClass = ToSeverityClass(severity);

                    sb.Append($@"
        <div class='finding'>
            <div class='finding-head {severityClass}'>
                <div class='finding-title'>{HtmlEncode(finding.Name ?? "N/A")}</div>
                <div class='severity-pill'>{HtmlEncode(severity)}</div>
            </div>
            <div class='finding-body'>
                <div class='row'>
                    <span class='label'>File</span>
                    <div class='value'>{HtmlEncode(finding.File ?? report.OriginalFileName)}</div>
                </div>
                <div class='row'>
                    <span class='label'>Line</span>
                    <div class='value'>{finding.Line}</div>
                </div>
                <div class='row'>
                    <span class='label'>Description</span>
                    <div class='value'>{HtmlEncode(finding.Context ?? finding.Match ?? finding.Name ?? "No description")}</div>
                </div>
                <div class='row'>
                    <span class='label'>Match</span>
                    <div class='value'>{HtmlEncode(finding.Match ?? "")}</div>
                </div>
                <div class='row'>
                    <span class='label'>Context</span>
                    <pre>{HtmlEncode(finding.Context ?? "")}</pre>
                </div>
            </div>
        </div>");
                }
            }

            sb.Append($@"
    </div>
</body>
</html>");

            return sb.ToString();
        }

        private StoredSourceCodeReviewReport? LoadReportById(string reportId)
        {
            var userId = GetCurrentUserId();
            var reportFolder = EnsureReportFolder(userId);
            var jsonPath = Path.Combine(reportFolder, $"{reportId}.json");
            var report = TryReadStoredReport(jsonPath);
            if (report == null || report.UserId != userId)
                return null;

            return report;
        }

        private StoredSourceCodeReviewReport? TryReadStoredReport(string path)
        {
            try
            {
                var json = System.IO.File.ReadAllText(path);
                return JsonSerializer.Deserialize<StoredSourceCodeReviewReport>(json, JsonOptions);
            }
            catch
            {
                return null;
            }
        }

        private string EnsureReportFolder(int userId)
        {
            var folder = Path.Combine(AppContext.BaseDirectory, "SourceCodeReviewReports", userId.ToString(CultureInfo.InvariantCulture));
            Directory.CreateDirectory(folder);
            return folder;
        }

        private static int GetSeverityCount(Dictionary<string, int> counts, string key)
        {
            return counts.TryGetValue(key, out var value) ? value : 0;
        }

        private string GetDownloadUrl(string reportId) => $"/api/source-code-review/reports/{reportId}/download";

        private int GetCurrentUserId()
        {
            var claim = User.FindFirst(ClaimTypes.NameIdentifier);
            if (claim != null && int.TryParse(claim.Value, out var userId))
                return userId;

            throw new UnauthorizedAccessException("User ID not found in token.");
        }

        private static string HtmlEncode(string? value) => System.Net.WebUtility.HtmlEncode(value ?? string.Empty);

        private static string MakeSafeFileStem(string fileName)
        {
            var stem = Path.GetFileNameWithoutExtension(fileName);
            var invalid = Path.GetInvalidFileNameChars();
            var safe = new string(stem.Select(ch => invalid.Contains(ch) ? '_' : ch).ToArray());
            return string.IsNullOrWhiteSpace(safe) ? "source-review" : safe;
        }

        private static string ToSeverityClass(string severity)
        {
            var lower = severity.ToLowerInvariant();
            if (lower.Contains("critical")) return "critical";
            if (lower.Contains("high")) return "high";
            if (lower.Contains("medium")) return "medium";
            if (lower.Contains("low")) return "low";
            return "info";
        }

        private static void TryDeleteFile(string path)
        {
            try
            {
                if (System.IO.File.Exists(path))
                    System.IO.File.Delete(path);
            }
            catch { }
        }

        private sealed class SourceCodeReviewScannerReportDto
        {
            [JsonPropertyName("engine")]
            public string? Engine { get; set; }

            [JsonPropertyName("status")]
            public string? Status { get; set; }

            [JsonPropertyName("file")]
            public string? File { get; set; }

            [JsonPropertyName("file_size")]
            public long FileSize { get; set; }

            [JsonPropertyName("overall_status")]
            public string? OverallStatus { get; set; }

            [JsonPropertyName("total_findings")]
            public int TotalFindings { get; set; }

            [JsonPropertyName("severity_breakdown")]
            public Dictionary<string, int>? SeverityBreakdown { get; set; }

            [JsonPropertyName("findings")]
            public List<SourceCodeReviewFindingDto>? Findings { get; set; }
        }

        private sealed class SourceCodeReviewFindingDto
        {
            [JsonPropertyName("vuln_id")]
            public string? VulnId { get; set; }

            [JsonPropertyName("name")]
            public string? Name { get; set; }

            [JsonPropertyName("severity")]
            public string? Severity { get; set; }

            [JsonPropertyName("file")]
            public string? File { get; set; }

            [JsonPropertyName("line")]
            public int Line { get; set; }

            [JsonPropertyName("match")]
            public string? Match { get; set; }

            [JsonPropertyName("context")]
            public string? Context { get; set; }
        }

        private sealed class StoredSourceCodeReviewReport
        {
            [JsonPropertyName("reportId")]
            public string ReportId { get; set; } = string.Empty;

            [JsonPropertyName("userId")]
            public int UserId { get; set; }

            [JsonPropertyName("originalFileName")]
            public string OriginalFileName { get; set; } = string.Empty;

            [JsonPropertyName("fileName")]
            public string FileName { get; set; } = string.Empty;

            [JsonPropertyName("createdAt")]
            public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

            [JsonPropertyName("completedAt")]
            public DateTime? CompletedAt { get; set; }

            [JsonPropertyName("htmlFileName")]
            public string HtmlFileName { get; set; } = string.Empty;

            [JsonPropertyName("jsonFileName")]
            public string JsonFileName { get; set; } = string.Empty;

            [JsonPropertyName("engine")]
            public string? Engine { get; set; }

            [JsonPropertyName("status")]
            public string? Status { get; set; }

            [JsonPropertyName("file_size")]
            public long FileSize { get; set; }

            [JsonPropertyName("overall_status")]
            public string? OverallStatus { get; set; }

            [JsonPropertyName("total_findings")]
            public int TotalFindings { get; set; }

            [JsonPropertyName("severity_breakdown")]
            public Dictionary<string, int> SeverityBreakdown { get; set; } = new();

            [JsonPropertyName("findings")]
            public List<SourceCodeReviewFindingDto> Findings { get; set; } = new();
        }
    }
}
