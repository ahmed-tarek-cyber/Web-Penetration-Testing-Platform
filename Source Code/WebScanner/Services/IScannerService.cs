using System.Threading.Tasks;
using WebScanner.Models;

namespace WebScanner.Services
{
    public interface IScannerService
    {
        Task<ScanReport> RunScanAsync(ScanRequest request);
    }
}
