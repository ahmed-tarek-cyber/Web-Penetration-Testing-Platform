using Microsoft.AspNetCore.SignalR;

namespace WebScanner.SignalR
{
    public class ChatHub:Hub
    {
        public async Task JoinChat(string chatId)
        {
          await Groups.AddToGroupAsync(Context.ConnectionId, chatId);
        }
    }
}
