using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using WebScanner.Data;
using WebScanner.Interfaces;
using WebScanner.Models;
using WebScanner.SignalR;

namespace WebScanner.Services
{
    public class ChatService
    {
        private readonly AppDbContext _db;
        private readonly IChatAiService _ai;
        private readonly IHubContext<ChatHub> _hub;

        public ChatService(AppDbContext db, IChatAiService ai, IHubContext<ChatHub> hub)
        {
            _db = db;
            _ai = ai;
            _hub = hub;
        }

        public async Task<List<ChatMessage>> GetChatHistoryByScan(int userId, string reportId)
        {
            if (string.IsNullOrEmpty(reportId)) return new List<ChatMessage>();

            var session = await _db.ChatSessions
                .FirstOrDefaultAsync(s => s.UserId == userId &&
                                         (s.ScanReportId == reportId || s.SourceCodeReviewReportId == reportId));

            if (session == null) return new List<ChatMessage>();

            return await _db.ChatMessages
                .Where(m => m.ChatSessionId == session.Id)
                .OrderBy(m => m.CreatedAt)
                .ToListAsync();
        }

        public async Task<object> SendMessage(int userId, ChatRequest req)
        {
            try
            {
                ChatSession chat = null;
                string? sourceCodeId = req.SourceCodeReviewReportId?.ToString().Trim();
                string? scanId = req.ScanReportId?.ToString().Trim();

                if (string.IsNullOrEmpty(sourceCodeId) && string.IsNullOrEmpty(scanId))
                {
                    throw new ArgumentException("Both ScanReportId and SourceCodeReviewReportId are missing.");
                }

                if (!string.IsNullOrEmpty(sourceCodeId))
                {
                    chat = await _db.ChatSessions
                        .FirstOrDefaultAsync(s => s.SourceCodeReviewReportId == sourceCodeId && s.UserId == userId);

                    if (chat == null)
                    {
                        var reportExists = await _db.SourceCodeReviewReports.AnyAsync(r => r.Id == sourceCodeId);

                        chat = new ChatSession
                        {
                            UserId = userId,
                            SourceCodeReviewReportId = sourceCodeId,
                            ScanReportId = null,
                            CreatedAt = DateTime.Now
                        };
                        _db.ChatSessions.Add(chat);
                        await _db.SaveChangesAsync();
                    }
                }
                else if (!string.IsNullOrEmpty(scanId))
                {
                    chat = await _db.ChatSessions
                        .FirstOrDefaultAsync(s => s.ScanReportId == scanId && s.UserId == userId);

                    if (chat == null)
                    {
                        chat = new ChatSession
                        {
                            UserId = userId,
                            ScanReportId = scanId,
                            SourceCodeReviewReportId = null,
                            CreatedAt = DateTime.Now
                        };
                        _db.ChatSessions.Add(chat);
                        await _db.SaveChangesAsync();
                    }
                }

                string finalUserMessage = !string.IsNullOrEmpty(req.Message)
                    ? req.Message
                    : (!string.IsNullOrEmpty(req.AiPromptContext) ? "Reviewing findings..." : "Hello SphinxEye AI");

                var userMsg = new ChatMessage
                {
                    ChatSessionId = chat.Id,
                    Role = "user",
                    Content = finalUserMessage,
                    CreatedAt = DateTime.Now
                };
                _db.ChatMessages.Add(userMsg);
                await _db.SaveChangesAsync();

                try
                {
                    await _hub.Clients.Group(chat.Id.ToString())
                        .SendAsync("ReceiveMessage", new { role = "user", content = finalUserMessage });
                }
                catch (Exception ex) { Console.WriteLine($"[SignalR Warning]: {ex.Message}"); }

                string promptToSend = !string.IsNullOrEmpty(req.AiPromptContext) ? req.AiPromptContext : finalUserMessage;
                string aiReply = "No response from AI Service.";

                try
                {
                    if (_ai != null)
                    {
                        aiReply = await _ai.AskAsync(promptToSend);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[AI Service Error]: {ex.Message}");
                    aiReply = $"Sorry, I encountered an error while processing the AI request. Details: {ex.Message}";
                }

                var aiMsg = new ChatMessage
                {
                    ChatSessionId = chat.Id,
                    Role = "assistant",
                    Content = aiReply,
                    CreatedAt = DateTime.Now
                };
                _db.ChatMessages.Add(aiMsg);
                await _db.SaveChangesAsync();

                try
                {
                    await _hub.Clients.Group(chat.Id.ToString())
                        .SendAsync("ReceiveMessage", new { role = "assistant", content = aiReply });
                }
                catch (Exception ex) { Console.WriteLine($"[SignalR Warning]: {ex.Message}"); }

                return new { chatId = chat.Id, reply = aiReply };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[CRITICAL ERROR IN CHATSERVICE]: {ex.ToString()}");
                throw;
            }
        }
    }
}
