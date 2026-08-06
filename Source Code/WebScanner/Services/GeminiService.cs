using System.Text.Json;
using WebScanner.Interfaces;

namespace WebScanner.Services
{
    public class GeminiService : IChatAiService
    {

        private readonly HttpClient _http;
        private readonly string _apiKey;  // = "YOUR_API_KEY";

        public GeminiService(HttpClient http, IConfiguration config)
        {
            _http = http;
            _apiKey = config["ChatAi:ApiKey"];
        }
 
        public async Task<string> AskAsync(string message)
        {
            var request = new
            {
                contents = new[]
                {
            new {
                parts = new[]
                {
                    new {
                        text = $"You are a cybersecurity assistant.\nUser: {message}"
                    }
                }
            }
        }
            };

            var url = $"https://generativelanguage.googleapis.com/v1/models/gemini-2.5-flash:generateContent?key={_apiKey}";

            var response = await _http.PostAsJsonAsync(url, request);

            var json = await response.Content.ReadAsStringAsync();

            Console.WriteLine(json); // debugging

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            // 🔴 check لو فيه error
            if (root.TryGetProperty("error", out var error))
            {
                var msg = error.GetProperty("message").GetString();
                return $"Error from AI: {msg}";
            }

            // 🟢 safe extraction
            if (root.TryGetProperty("candidates", out var candidates))
            {
                var text = candidates[0]
                    .GetProperty("content")
                    .GetProperty("parts")[0]
                    .GetProperty("text")
                    .GetString();

                return text ?? "No response";
            }

            return "Unexpected response from AI";
        }
    }


}
 