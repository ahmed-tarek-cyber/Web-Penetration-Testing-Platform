using System;
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using System.IO;

namespace YourBackend.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ScannersController : ControllerBase
    {
        // POST api/scanners/run
        // Body JSON: { "scanner": "xss", "target": "https://example.com" }
        [HttpPost("run")]
        public async Task<IActionResult> RunScanner([FromBody] ScannerRequest req)
        {
            if (string.IsNullOrEmpty(req?.Scanner) || string.IsNullOrEmpty(req?.Target))
                return BadRequest("scanner and target are required.");

            // Adjust path to the NativeScanners executable or dotnet run command depending on deployment.
            // This example assumes NativeScanners executable is placed in a known folder on the server.
            string exePath = Path.Combine(AppContext.BaseDirectory, "NativeScanners", "NativeScanners.exe");
            string args = $"{req.Scanner} \"{req.Target}\"";

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = exePath, // or "dotnet"
                    Arguments = args,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var p = Process.Start(psi))
                {
                    var outp = await p.StandardOutput.ReadToEndAsync();
                    var err = await p.StandardError.ReadToEndAsync();
                    p.WaitForExit();
                    return Ok(new { exitCode = p.ExitCode, stdout = outp, stderr = err });
                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = ex.Message });
            }
        }
    }

    public class ScannerRequest
    {
        public string Scanner { get; set; }
        public string Target { get; set; }
    }
}