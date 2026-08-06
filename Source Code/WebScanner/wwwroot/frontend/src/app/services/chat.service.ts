import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import * as signalR from '@microsoft/signalr';
import { Subject, Observable } from 'rxjs';
import { ChatMessage } from '../classes/chat-message';

@Injectable({
  providedIn: 'root'
})
export class ChatService {
  private hubConnection!: signalR.HubConnection;
  public messageReceived = new Subject<any>();
  private baseUrl = 'http://localhost:5000';

  constructor(private http: HttpClient) {
    this.buildConnection();
    this.startConnection();
  }

  private buildConnection() {
    this.hubConnection = new signalR.HubConnectionBuilder()
      .withUrl(`${this.baseUrl}/chatHub`)
      .withAutomaticReconnect()
      .build();
  }

  private startConnection() {
    this.hubConnection.start()
      .then(() => console.log('SignalR Connected!'))
      .catch(err => console.log('SignalR Connection Error: ', err));
  }

  getChatHistory(scanReportId: string): Observable<any[]> {
    return this.http.get<any[]>(`${this.baseUrl}/api/chat/history/${scanReportId}`);
  }

  async joinChatGroup(chatId: string) {
    if (this.hubConnection.state === signalR.HubConnectionState.Connected) {
      await this.hubConnection.invoke('JoinChat', chatId);
    }
  }

  public listenToMessages() {
    this.hubConnection.on('ReceiveMessage', (data: any) => {
      this.messageReceived.next(data);
    });
  }

  postMessage(payload: { scanReportId: string | null, sourceCodeReviewReportId: string | null, message: string, aiPromptContext: string }): Observable<any> {
    return this.http.post(`${this.baseUrl}/api/chat/send`, payload);
  }
}
