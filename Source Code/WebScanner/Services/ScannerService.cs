using Microsoft.Extensions.Logging;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using WebScanner.Data;
using WebScanner.Models;

namespace WebScanner.Services
{
    public class ScannerService : IScannerService
    {
        private readonly AppDbContext _db;
        private readonly ILogger<ScannerService> _logger;
        private readonly IHttpClientFactory _httpFactory;

        // تحديد عدد العمليات المتزامنة لتجنب استهلاك موارد السيرفر بالكامل
        private static readonly SemaphoreSlim _concurrencyLimiter = new SemaphoreSlim(5);

        public ScannerService(AppDbContext db, ILogger<ScannerService> logger, IHttpClientFactory httpFactory)
        {
            _db = db;
            _logger = logger;
            _httpFactory = httpFactory;
        }

        public async Task<ScanReport> RunScanAsync(ScanRequest request)
        {
            var timer = Stopwatch.StartNew();
            var report = new ScanReport
            {
                Url = NormalizeUrl(request.Url),
                CreatedAt = DateTime.UtcNow,
                Results = new List<Vulnerability>(),
                Status = "Running"
            };

            _logger.LogInformation($"[*] Starting Scan on: {report.Url}");

            try
            {
                // 1. الزحف لاستكشاف الصفحات
                var allPages = await CrawlWebsiteAsync(report.Url);
                _logger.LogInformation($"[+] Crawled {allPages.Count} pages. Starting scripts...");

                // 2. تشغيل طبقة البايثون (تمت إضافة الأدوات الجديدة هنا)
                await RunPythonLayerParallel(report, allPages);

                // 3. تحديد حالة التقرير النهائية
                ApplyStatus(report);
                report.CompletedAt = DateTime.UtcNow;
                timer.Stop();

                // 4. ربط النتائج بالتقرير
                if (report.Results != null)
                {
                    foreach (var vuln in report.Results)
                    {
                        vuln.ScanReport = report;
                    }
                }

                _logger.LogInformation($"[Done] Scan finished in {timer.Elapsed.TotalSeconds:N1}s. Found {report.Results?.Count ?? 0} issues.");
            }
            catch (Exception ex)
            {
                _logger.LogError($"[!] Scan Failed: {ex.Message}");
                report.Status = "Failed";
            }
            finally
            {
                _db.ChangeTracker.AutoDetectChangesEnabled = true;
            }

            return report;
        }

        private async Task<List<string>> CrawlWebsiteAsync(string baseUrl)
        {
            var foundUrls = new List<string> { baseUrl };
            var visited = new HashSet<string> { baseUrl };
            var toVisit = new Queue<string>();
            toVisit.Enqueue(baseUrl);

            using var client = _httpFactory.CreateClient();
            client.Timeout = TimeSpan.FromSeconds(5); // زيادة المهلة قليلاً
            client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebScanner/1.0");

            int counter = 0;
            int maxPages = 20; // الحد الأقصى للصفحات التي يتم فحصها

            while (toVisit.Count > 0 && counter < maxPages)
            {
                var current = toVisit.Dequeue();
                counter++;
                try
                {
                    var html = await client.GetStringAsync(current);
                    var matches = Regex.Matches(html, @"href\s*=\s*[""']([^""']+)[""']", RegexOptions.IgnoreCase);

                    foreach (Match match in matches)
                    {
                        var link = match.Groups[1].Value;
                        var absUrl = ToAbsoluteUrl(baseUrl, link);

                        if (absUrl != null && absUrl.StartsWith(baseUrl) && !visited.Contains(absUrl))
                        {
                            visited.Add(absUrl);
                            toVisit.Enqueue(absUrl);
                            foundUrls.Add(absUrl);
                        }
                    }
                }
                catch { /* Ignore crawl errors */ }
            }
            return foundUrls;
        }

        private async Task RunPythonLayerParallel(ScanReport report, List<string> pages)
        {
            var tasks = new List<Task<List<Vulnerability>>>();

            // ✅ قائمة الفحوصات التي تعمل على كل صفحة (Page-Level)
            var pageScripts = new[]
            {
                "run_xss.py",
                "run_nosql.py",
                "run_sensitive.py",
                "run_idor.py",
                "run_traversal.py",  // [NEW] Directory Traversal
                "run_redirect.py"    // [NEW] Open Redirect
            };

            // ✅ قائمة الفحوصات التي تعمل مرة واحدة للموقع (Site-Level)
            var siteScripts = new[]
            {
                "run_auth.py",
                "run_csrf.py",
                "run_sqlmap.py",
                "run_recon.py"
            };

            // تشغيل سكربتات الصفحات لكل رابط تم اكتشافه
            foreach (var p in pages)
                foreach (var s in pageScripts)
                    tasks.Add(RunPythonScriptSafe(s, p));

            // تشغيل سكربتات الموقع مرة واحدة على الرابط الرئيسي
            foreach (var s in siteScripts)
                tasks.Add(RunPythonScriptSafe(s, report.Url));

            // انتظار انتهاء جميع المهام وتجميع النتائج
            var results = await Task.WhenAll(tasks);

            foreach (var res in results)
            {
                if (res != null && res.Count > 0)
                {
                    report.Results.AddRange(res);
                }
            }
        }

        private async Task<List<Vulnerability>> RunPythonScriptSafe(string script, string url)
        {
            // استخدام SemaphoreSlim لضمان عدم تشغيل عدد كبير جداً من ملفات البايثون في نفس الوقت
            await _concurrencyLimiter.WaitAsync();
            try
            {
                return await RunPythonScript(script, url);
            }
            finally
            {
                _concurrencyLimiter.Release();
            }
        }

        private async Task<List<Vulnerability>> RunPythonScript(string scriptName, string targetUrl)
        {
            var vulns = new List<Vulnerability>();
            string baseDir = AppContext.BaseDirectory;
            // افتراض أن ملفات البايثون موجودة في مجلد Scanners/Wrappers
            string scriptPath = Path.Combine(baseDir, "Scanners", "Wrappers", scriptName);
            string scriptDirectory = Path.GetDirectoryName(scriptPath) ?? baseDir;
            string parentDirectory = Directory.GetParent(scriptDirectory)?.FullName ?? scriptDirectory;
            string outputJson = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid()}.json");

            if (!File.Exists(scriptPath))
            {
                _logger.LogError($"[X] Script missing: {scriptPath}");
                return vulns;
            }

            var startInfo = new ProcessStartInfo
            {
                FileName = "python", // تأكد أن python مضاف لمتغيرات البيئة PATH
                Arguments = $"\"{scriptName}\" --url \"{targetUrl}\" --out \"{outputJson}\"",
                WorkingDirectory = scriptDirectory,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            // إضافة مسارات بايثون لضمان استيراد الوحدات بشكل صحيح
            string pythonPaths = $"{scriptDirectory}{Path.PathSeparator}{parentDirectory}";
            if (startInfo.EnvironmentVariables.ContainsKey("PYTHONPATH"))
                startInfo.EnvironmentVariables["PYTHONPATH"] += Path.PathSeparator + pythonPaths;
            else
                startInfo.EnvironmentVariables.Add("PYTHONPATH", pythonPaths);

            _logger.LogInformation($"[->] Running {scriptName} on {targetUrl}...");

            try
            {
                using var process = new Process { StartInfo = startInfo };

                using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(3)); // زيادة الوقت لـ 3 دقائق

                process.Start();

                try
                {
                    await process.WaitForExitAsync(cts.Token);
                }
                catch (OperationCanceledException)
                {
                    _logger.LogWarning($"[!] Timeout: Script {scriptName} took too long. Killing process.");
                    try { process.Kill(); } catch { }
                }

                string stderr = await process.StandardError.ReadToEndAsync();
                if (!string.IsNullOrEmpty(stderr) && !stderr.Contains("warning", StringComparison.OrdinalIgnoreCase))
                {
                    // يمكن تفعيل هذا السطر للـ Debugging إذا واجهت مشاكل
                    // _logger.LogDebug($"[Python Log] {scriptName}: {stderr}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"[Process Error] {scriptName}: {ex.Message}");
            }

            // قراءة ملف JSON الناتج
            if (File.Exists(outputJson))
            {
                try
                {
                    var json = await File.ReadAllTextAsync(outputJson);

                    // تنظيف النص للعثور على مصفوفة JSON فقط (لتجاهل أي طباعة زائدة)
                    if (json.Contains("["))
                    {
                        int startIndex = json.IndexOf("[");
                        int endIndex = json.LastIndexOf("]");
                        if (endIndex > startIndex)
                        {
                            json = json.Substring(startIndex, endIndex - startIndex + 1);
                            var results = JsonSerializer.Deserialize<List<PythonVulnResult>>(json,
                                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

                            if (results != null)
                            {
                                vulns = results.Select(r => new Vulnerability
                                {
                                    Name = r.Name ?? r.Type ?? "Unknown Issue",
                                    Severity = r.Severity ?? "Low",
                                    Description = r.Description ?? "Detected by scanner",
                                    Location = r.Location ?? targetUrl,
                                    Payload = r.Payload ?? "",
                                    Payload2 = r.Payload2,
                                    Source = $"Python: {scriptName}",
                                    DetectedAt = DateTime.UtcNow
                                }).ToList();
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError($"[JSON Parse Error] {scriptName}: {ex.Message}");
                }
                finally
                {
                    try { File.Delete(outputJson); } catch { }
                }
            }

            return vulns;
        }

        private string? ToAbsoluteUrl(string baseUri, string relative)
        {
            try { return new Uri(new Uri(baseUri), relative).ToString(); }
            catch { return null; }
        }

        private string NormalizeUrl(string url)
        {
            if (string.IsNullOrWhiteSpace(url)) return "";
            url = url.Trim();
            if (url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                return url;
            }
            return "http://" + url;
        }

        private void ApplyStatus(ScanReport report)
        {
            if (report.Results.Any(r => r.Severity?.ToLower() == "critical" || r.Severity?.ToLower() == "high"))
                report.Status = "Dangerous";
            else if (report.Results.Any(r => r.Severity?.ToLower() == "medium"))
                report.Status = "Suspicious";
            else if (report.Results.Any())
                report.Status = "Safe (Info Only)";
            else
                report.Status = "Safe";
        }

        // كلاس مساعد لفك تشفير JSON القادم من بايثون
        private class PythonVulnResult
        {
            public string? Name { get; set; }
            public string? Type { get; set; }
            public string? Severity { get; set; }
            public string? Description { get; set; }
            public string? Location { get; set; }
            public string? Payload { get; set; }
            public string? Payload2 { get; set; }
        }
    }
}