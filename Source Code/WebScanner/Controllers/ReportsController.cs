using Microsoft.AspNetCore.Mvc;
using WebScanner.Models;
using WebScanner.Data;
using System.Linq;
using System.Text;
using System.Collections.Generic;
using System;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims; 
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using System.Web; 

[Authorize] 
[ApiController]
[Route("api/[controller]")]
public class ReportsController : ControllerBase
{
    private readonly AppDbContext _db;
    public ReportsController(AppDbContext db) => _db = db;

    
    private int GetCurrentUserId()
    {
        var claim = User.FindFirst(ClaimTypes.NameIdentifier);
        if (claim != null && int.TryParse(claim.Value, out int userId))
        {
            return userId;
        }
        
        throw new UnauthorizedAccessException("User ID not found in token.");
    }

    
    [HttpGet]
    public IActionResult List()
    {
        int userId = GetCurrentUserId(); 

        var list = _db.Reports
               .Where(r => r.UserId == userId) 
               .Select(r => new
               {
                   r.Id,
                   r.Url,
                   r.Status,
                   r.CreatedAt,
                   UniqueFindings = _db.Vulnerabilities
                                    .Where(v => v.ScanReportId == r.Id)
                                    .Select(v => v.Name)
                                    .Distinct()
                                    .ToList(),
                   TotalCount = _db.Vulnerabilities.Count(v => v.ScanReportId == r.Id)
               })
               .OrderByDescending(r => r.CreatedAt)
               .ToList();
        return Ok(list);
    }

    
    [HttpGet("{id}/vulnerabilities")]
    public IActionResult GetVulnerabilities(string id)
    {
        int userId = GetCurrentUserId();

       
        if (!_db.Reports.Any(r => r.Id == id && r.UserId == userId))
        {
            return Unauthorized(new { Message = "Report not found or access denied." });
        }

        var data = _db.Vulnerabilities
                        .Where(v => v.ScanReportId == id)
                        .Select(v => new
                        {
                            v.Name,
                            v.Severity,
                            v.Description,
                            v.Location,
                            v.Color,
                            v.Payload 
                        })
                        .ToList();

        return Ok(new { Data = data });
    }

    
    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteReport(string id)
    {
        int userId = GetCurrentUserId();

        var report = await _db.Reports
                              .Include(r => r.Results)
                              .FirstOrDefaultAsync(r => r.Id == id && r.UserId == userId); 

        if (report == null)
        {
            return NotFound(new { Message = "Report not found or access denied." });
        }

       
        _db.Vulnerabilities.RemoveRange(report.Results);
        
        _db.Reports.Remove(report);
        
        await _db.SaveChangesAsync();

        return Ok(new { Message = "Report deleted successfully." });
    }

   
    [HttpGet("{id}/download")]
    public async Task<IActionResult> DownloadReport(string id)
    {
        int userId = GetCurrentUserId();

        // 1. جلب التقرير وثغراته، مع التحقق من الملكية
        var report = await _db.Reports
                              .Include(r => r.Results)
                              .FirstOrDefaultAsync(r => r.Id == id && r.UserId == userId);

        if (report == null)
        {
            return NotFound("Report not found or access denied.");
        }

     
        string html = BuildEnhancedReportHtml(report, report.Results.ToList());

        // 3. تحويل الـ HTML إلى Bytes
        byte[] bytes = Encoding.UTF8.GetBytes(html);

        
        string safeUrl = report.Url.Replace("http://", "").Replace("https://", "").Replace("/", "_").Replace(":", "");
        string fileName = $"SphinxEye_Report_{safeUrl}_{DateTime.Now:yyyyMMdd_HHmm}.html";

        // 5. إرجاع الملف كـ FileResult
        return File(bytes, "text/html", fileName);
    }

    // =========================================================
    // دالة بناء التقرير (BuildEnhancedReportHtml)
    // =========================================================
    private string BuildEnhancedReportHtml(ScanReport report, List<Vulnerability> vulns)
    {
        var sb = new StringBuilder();

        
        sb.Append($@"<!DOCTYPE html>
        <html lang='en'>
        <head>
            <meta charset='UTF-8'>
            <title>Security Report</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f7f6; color: #333; margin: 0; padding: 20px; }}
                .container {{ max-width: 900px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }}
                
                header {{ text-align: center; border-bottom: 2px solid #eee; padding-bottom: 20px; margin-bottom: 30px; }}
                h1 {{ color: #d9534f; margin: 0; font-size: 28px; }}
                .meta {{ color: #777; font-size: 14px; margin-top: 10px; }}
                
                .summary-box {{ display: flex; justify-content: space-around; background: #fafafa; padding: 20px; border-radius: 8px; margin-bottom: 30px; border: 1px solid #eee; }}
                .stat-item {{ text-align: center; }}
                .stat-number {{ font-size: 24px; font-weight: bold; }}
                .stat-label {{ color: #777; font-size: 12px; }}

                .badge {{ padding: 4px 8px; border-radius: 4px; color: white; font-size: 12px; font-weight: bold; display: inline-block; }}
                .bg-high {{ background-color: #dc3545; }}
                .bg-medium {{ background-color: #ffc107; color: #333; }}
                .bg-low {{ background-color: #0d6efd; }}
                .bg-info {{ background-color: #28a745; }}

                .vuln-card {{ border: 1px solid #eee; border-radius: 6px; margin-bottom: 15px; overflow: hidden; box-shadow: 0 2px 5px rgba(0,0,0,0.05); }}
                .vuln-header {{ background-color: #f8f8f8; padding: 12px 15px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #eee; }}
                .vuln-title {{ font-weight: bold; font-size: 16px; color: #333; }}
                .vuln-body {{ padding: 15px; }}
                .label {{ font-weight: 600; color: #555; display: block; margin-top: 10px; }}
                .value {{ margin-bottom: 10px; padding: 5px; background: #f9f9f9; border: 1px solid #eee; border-radius: 4px; white-space: pre-wrap; word-break: break-all; }}
                .url-text {{ color: #007bff; font-family: monospace; }}
                .payload-box {{ font-family: 'Courier New', monospace; background-color: #212529; color: #f8f9fa; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 13px; }}
                
                footer {{ text-align: center; border-top: 1px solid #eee; padding-top: 20px; margin-top: 30px; color: #aaa; font-size: 12px; }}

            </style>
        </head>
        <body>
            <div class='container'>
                <header>
                    <h1>Security Report</h1>
                    <p class='meta'>URL: <a href='{report.Url}' target='_blank'>{report.Url}</a></p>
                    <p class='meta'>Scan Date: {report.CreatedAt.ToLocalTime():yyyy-MM-dd HH:mm:ss}</p>
                </header>

                <div class='summary-box'>");

        // 2. إحصائيات الثغرات
        var highCount = vulns.Count(v => v.Severity?.ToLower() == "high" || v.Severity?.ToLower() == "critical");
        var mediumCount = vulns.Count(v => v.Severity?.ToLower() == "medium");
        var lowCount = vulns.Count(v => v.Severity?.ToLower() == "low");
        var infoCount = vulns.Count(v => v.Severity?.ToLower() == "info" || v.Severity?.ToLower() == "informational");
        var totalCount = vulns.Count;

        sb.Append($@"
                    <div class='stat-item'>
                        <span class='stat-number' style='color:#dc3545;'>{highCount}</span>
                        <span class='stat-label'>HIGH/CRITICAL</span>
                    </div>
                    <div class='stat-item'>
                        <span class='stat-number' style='color:#ffc107;'>{mediumCount}</span>
                        <span class='stat-label'>MEDIUM</span>
                    </div>
                    <div class='stat-item'>
                        <span class='stat-number' style='color:#0d6efd;'>{lowCount}</span>
                        <span class='stat-label'>LOW</span>
                    </div>
                    <div class='stat-item'>
                        <span class='stat-number' style='color:#28a745;'>{totalCount}</span>
                        <span class='stat-label'>TOTAL FINDINGS</span>
                    </div>
                </div>

                <h2>Vulnerability Details</h2>
        ");

       
        if (!vulns.Any())
        {
            sb.Append("<p style='text-align:center; color:#5cb85c; font-size:1.1rem;'>No vulnerabilities found.</p>");
        }
        else
        {
            foreach (var v in vulns.OrderBy(v => v.Severity))
            {
                
                string badgeClass = "bg-info";
                if (v.Severity?.ToLower().Contains("critical") == true) badgeClass = "bg-high";
                else if (v.Severity?.ToLower().Contains("high") == true) badgeClass = "bg-high";
                else if (v.Severity?.ToLower().Contains("medium") == true) badgeClass = "bg-medium";
                else if (v.Severity?.ToLower().Contains("low") == true) badgeClass = "bg-low";

                string name = HttpUtility.HtmlEncode(v.Name ?? "N/A");
                string severity = HttpUtility.HtmlEncode(v.Severity ?? "N/A");
                string description = HttpUtility.HtmlEncode(v.Description ?? "No description provided.");
                string location = HttpUtility.HtmlEncode(v.Location ?? "N/A");

                string payloadHtml = string.IsNullOrEmpty(v.Payload)
                    ? ""
                    : $@"
                        <span class='label'>Payload / Evidence:</span>
                        <div class='payload-box'>{HttpUtility.HtmlEncode(v.Payload)}</div>
                    ";

                sb.Append($@"\r\n                <div class='vuln-card'>
                    <div class='vuln-header'>
                        <span class='vuln-title'>{name}</span>
                        <span class='badge {badgeClass}'>{severity}</span>
                    </div>
                    <div class='vuln-body'>
                        <span class='label'>Location:</span>
                        <div class='value url-text'>{location}</div>

                        <span class='label'>Description:</span>
                        <div class='value'>{description}</div>

                        {payloadHtml}
                    </div>
                </div>");
            }
        }

        sb.Append($@"\r\n            </div>
        </body>
        </html>");

        return sb.ToString();
    }
}