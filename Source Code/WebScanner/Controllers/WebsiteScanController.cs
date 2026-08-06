using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using WebScanner.Models;
using WebScanner.Services;
using WebScanner.Data; 
using System.Security.Claims; 
using System.Linq; 

namespace WebScanner.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class ScanController : ControllerBase
    {
        private readonly IScannerService _scanner;
        private readonly AppDbContext _db; 

        
        public ScanController(IScannerService scanner, AppDbContext db)
        {
            _scanner = scanner;
            _db = db;
        }

        [HttpPost("run")]
        public async Task<IActionResult> StartScan([FromBody] ScanRequest request)
        {
            if (string.IsNullOrEmpty(request.Url))
                return BadRequest("URL is required");

            
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier);
            if (userIdClaim == null || !int.TryParse(userIdClaim.Value, out int currentUserId))
            {
                return Unauthorized("User ID is missing or invalid in the token.");
            }

            
            var report = await _scanner.RunScanAsync(request);

            
            report.UserId = currentUserId;

            
            if (report.Results.Count > 0)
            {
                report.Status = "Dangerous";
            }
            else if (report.Status == "Running" || report.Status == "Pending")
            {
                report.Status = "Safe";
            }

            
            _db.Reports.Add(report);
            await _db.SaveChangesAsync();

            return Ok(new
            {
                Message = "Scan Completed",
                ReportId = report.Id,
                Status = report.Status,
                TotalIssues = report.Results.Count,
                DetailsUrl = $"/api/reports/{report.Id}/vulnerabilities"
            });
        }
    }
}