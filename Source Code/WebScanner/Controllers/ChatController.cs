using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using WebScanner.Interfaces;
using WebScanner.Models;
using WebScanner.Services;

namespace WebScanner.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ChatController : ControllerBase
    {
        private readonly IChatAiService _ai;
        private readonly ChatService _chat;

        public ChatController(IChatAiService ai, ChatService chat)
        {
            _ai = ai;
            _chat = chat;
        }

        [HttpPost]
        public async Task<IActionResult> Chat([FromBody] ChatRequest req)
        {
            var reply = await _ai.AskAsync(req.Message);
            return Ok(reply);
        }

        [Authorize]
        [HttpPost("send")]
        public async Task<IActionResult> Send([FromBody] ChatRequest req)
        {
            var userIdClaim = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier);
            if (userIdClaim == null) return Unauthorized(new { message = "User identity token missing." });

            int userId = int.Parse(userIdClaim.Value);

            try
            {
                var result = await _chat.SendMessage(userId, req);
                return Ok(result);
            }
            catch (ArgumentException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Chat API 500 Error]: {ex.Message}");
                return StatusCode(500, new
                {
                    message = "A database integrity or processing error occurred.",
                    details = ex.Message,
                    inner = ex.InnerException?.Message
                });
            }
        }

        [Authorize]
        [HttpGet("history/{scanReportId}")]
        public async Task<IActionResult> GetHistory(string scanReportId)
        {
            var userIdClaim = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier);
            if (userIdClaim == null) return Unauthorized();

            int userId = int.Parse(userIdClaim.Value);

            var history = await _chat.GetChatHistoryByScan(userId, scanReportId);

            if (history == null) return Ok(new List<ChatMessage>());

            return Ok(history);
        }
    }
}
