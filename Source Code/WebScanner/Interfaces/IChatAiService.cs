namespace WebScanner.Interfaces
{
    public interface IChatAiService
    {

        Task<string> AskAsync(string message);
    }
}
