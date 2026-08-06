using System.Collections.Concurrent;
using WebScanner.Models;

public class InMemoryStore
{
    public ConcurrentDictionary<string, InputField> Inputs { get; } = new();
    public ConcurrentDictionary<string, ScanReport> Reports { get; } = new();
}
