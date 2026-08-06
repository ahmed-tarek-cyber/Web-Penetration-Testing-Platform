
import { Component, OnInit, OnDestroy, ViewChild, ElementRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Subscription } from 'rxjs';
import { ActivatedRoute, Router } from '@angular/router';

import { ChatService } from '../../../services/chat.service';
import { ScanService } from '../../../services/scan.service';
import { AiContextService } from '../../../services/ai-context.service';
import { ChatContext } from '../../../classes/chat-context';

 
// Removed ngx-markdown import (rendering assistant messages as plain text to avoid dependency issues)

@Component({
  selector: 'app-ai-assistant',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './ai-assistant.component.html',
  styleUrls: ['./ai-assistant.component.css']
})
export class AiAssistantComponent implements OnInit, OnDestroy {

  scanId!: string;
  scanData: any = { chatId: 0, url: '', date: '', status: '', findingsCount: 0, uniqueFindings: [] };
  messages: any[] = [];
  newMessage: string = '';

  isLoadingResponse: boolean = false;
  isCodeReview: boolean = false;

  private messageSub!: Subscription;
  private contextSub!: Subscription;

  @ViewChild('chatMessages') private chatMessagesContainer!: ElementRef;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private scanService: ScanService,
    private chatService: ChatService,
    private aiContextService: AiContextService
  ) {
    const navigation = this.router.getCurrentNavigation();
    const stateData = navigation?.extras.state?.['data'];
    if (stateData) {
      this.mapScanData(stateData);
    }
  }

  ngOnInit() {
    const idParam = this.route.snapshot.paramMap.get('id');
    if (idParam) {
      this.scanId = idParam.trim();

      this.checkContextAndInit();
      this.chatService.listenToMessages();

      this.messageSub = this.chatService.messageReceived.subscribe({
        next: (msg: any) => {
          this.isLoadingResponse = false;
          const msgContent = msg.Content || msg.content || msg.Message || msg.message;
          const msgRole = msg.Role || msg.role;

          if (msgContent) {
            const exists = this.messages.some(m => m.Content === msgContent);
            if (!exists) {
              this.messages.push({ Role: msgRole, Content: msgContent });
              this.scrollToBottom();
            }
          }
        }
      });
    }
  }

  private checkContextAndInit() {
    const currentContext = this.aiContextService.getContextValue() as ChatContext;
    const navigationState = this.router.getCurrentNavigation()?.extras.state?.['data'];
    const resolvedState = navigationState || this.scanData;
    const resolvedType = currentContext?.type || resolvedState?.type;
    const isCodeReview = resolvedType === 'code';

    this.isCodeReview = isCodeReview;

    if (isCodeReview) {
      const codeFindings = resolvedState?.findingsCount ?? currentContext?.findingsCount ?? 0;
      this.scanData = {
        chatId: 0,
        url: resolvedState?.filePath || currentContext?.filePath || resolvedState?.fileName || 'main.js',
        date: resolvedState?.createdAt || resolvedState?.completedAt || new Date(),
        status: resolvedState?.status || resolvedState?.overallStatus || 'Scanned File',
        findingsCount: Number(codeFindings) || 0,
        uniqueFindings: currentContext?.uniqueFindings || resolvedState?.uniqueFindings || []
      };

      this.loadExistingHistoryAndSetupContext(this.scanId, true);
      return;
    }

    const reportFindings = resolvedState?.findingsCount ?? resolvedState?.totalCount ?? resolvedState?.TotalCount ?? 0;
    this.scanData = {
      chatId: 0,
      url: resolvedState?.Url || resolvedState?.url || resolvedState?.fileName || 'N/A',
      date: resolvedState?.CreatedAt || resolvedState?.createdAt || resolvedState?.completedAt || new Date(),
      status: resolvedState?.Status || resolvedState?.status || 'Scanned File',
      findingsCount: Number(reportFindings) || 0,
      uniqueFindings: resolvedState?.uniqueFindings || []
    };

    this.loadExistingHistoryAndSetupContext(this.scanId, false);
  }

  private loadExistingHistoryAndSetupContext(scanReportId: string, isCode: boolean) {
    this.chatService.getChatHistory(scanReportId).subscribe({
      next: (history: any[]) => {
        if (history && history.length > 0) {
          this.messages = history.map(m => ({
            Role: m.role || m.Role,
            Content: m.content || m.Content
          }));
          this.scrollToBottom();
        }

        this.chatService.joinChatGroup(scanReportId);

        if (isCode && (!history || history.length === 0)) {
          setTimeout(() => {
            this.triggerCodeReviewAutoSend();
          }, 300);
        }
      },
      error: (err) => {
        console.warn('History failed or empty, establishing fresh group connection.');
        this.chatService.joinChatGroup(scanReportId);

        if (isCode) {
          setTimeout(() => {
            this.triggerCodeReviewAutoSend();
          }, 300);
        }
      }
    });
  }

  private triggerCodeReviewAutoSend() {
    const context = this.aiContextService.getContextValue() as ChatContext;
    if (context && context.type === 'code') {
      this.newMessage = `I am reviewing a source code file: "${context.filePath}".\nStatus: Code review payload.\n\nPlease analyze this scan report and help me find, understand, and secure any potential vulnerabilities in this code.`;
      this.send();
    }
  }

  private mapScanData(data: any) {
    if (!data) return;
    this.scanData = {
      ...this.scanData,
      url: data.url || data.Url || data.fileName || data.FileName || 'N/A',
      date: data.createdAt || data.CreatedAt || data.completedAt || new Date(),
      status: data.status || data.Status || 'Scanned File',
      findingsCount: data.totalFindings || data.findingsCount || data.totalCount || 0,
      uniqueFindings: data.uniqueFindings || data.UniqueFindings || []
    };
  }

  loadScanInfo() {
    this.scanService.getScanDetails(this.scanId).subscribe({
      next: (data: any) => this.mapScanData(data),
      error: (err: any) => console.error('Failed to fetch standard scan info:', err)
    });
  }

  send() {
    if (!this.newMessage.trim()) return;

    const userMessageText = this.newMessage;
    this.messages.push({ Role: 'user', Content: userMessageText });
    this.newMessage = '';
    this.scrollToBottom();

    this.isLoadingResponse = true;

    let dynamicContext = "";
    const findings = this.scanData?.uniqueFindings || [];

    if (this.isCodeReview) {
      dynamicContext = `Context - Source Code Review for file: ${this.scanData.url}.\n`;
      dynamicContext += `Overall Status: ${this.scanData.status}\n`;
      dynamicContext += `Total Findings Found: ${this.scanData.findingsCount}\n`;

      if (findings && findings.length > 0) {
        dynamicContext += `Detailed Findings JSON Context:\n${JSON.stringify(findings, null, 2)}\n`;
      }
      dynamicContext += `\nUser Question: ${userMessageText}\n`;
    } else if (findings && findings.length > 0) {
      dynamicContext = `Context - Security scan report for website target: ${this.scanData.url || 'this target'}.\n`;
      dynamicContext += `Current Scan Findings:\n`;
      findings.forEach((f: any, index: number) => {
        const name = f.name || f.Name || 'Unknown Vulnerability';
        const severity = f.severity || f.Severity || 'Info';
        const description = f.description || f.Description || '';
        dynamicContext += `\n- [${index + 1}] ${name} (${severity}): ${description}`;
      });
      dynamicContext += `\n\nUser Question: ${userMessageText}\n`;
    } else {
      dynamicContext = userMessageText;
    }

    const body = {
      scanReportId: this.isCodeReview ? null : this.scanId,
      sourceCodeReviewReportId: this.isCodeReview ? this.scanId : null,
      message: userMessageText,
      aiPromptContext: dynamicContext
    };

    this.chatService.postMessage(body).subscribe({
      next: (res: any) => {
        if (res?.reply || res?.Reply) {
          this.isLoadingResponse = false;
          const aiReply = res.reply || res.Reply;
          const aiExists = this.messages.some(m => m.Content === aiReply);
          if (!aiExists) {
            this.messages.push({ Role: 'assistant', Content: aiReply });
            this.scrollToBottom();
          }
        }
      },
      error: (err) => {
        this.isLoadingResponse = false;
        console.error('Error sending chat message:', err);
      }
    });
  }

  quickAction(actionType: string) {
    this.isLoadingResponse = true;

    const targetUrl = this.scanData?.url || 'this target';
    let systemContext = `Context - Vulnerability Findings for ${targetUrl}:\n`;
    const findings = this.scanData?.uniqueFindings || [];

    if (findings && findings.length > 0) {
      findings.forEach((f: any, index: number) => {
        const name = f.name || f.Name || f.title || 'Vulnerability';
        const severity = f.severity || f.Severity || 'Warning';
        const description = f.description || f.Description || '';
        systemContext += `\n[${index + 1}] ${name} (${severity}): ${description}`;
      });
    } else {
      systemContext += `No structural findings listed yet for target: ${targetUrl}`;
    }

    let userViewMessage = "";
    let aiTask = "";

    switch (actionType) {
      case 'explain':
        userViewMessage = "🔍 Please explain the vulnerabilities found in this scan.";
        aiTask = "Explain these risks deeply and simply based on the context provided.";
        break;
      case 'fix':
        userViewMessage = "🛠️ How can I fix these security issues?";
        aiTask = "Provide remediation steps for each vulnerability listed.";
        break;
      case 'code':
        userViewMessage = "💻 Show me secure code examples.";
        aiTask = "Generate secure code examples to fix or mitigate these risks.";
        break;
      default:
        userViewMessage = "Please analyze this report.";
        aiTask = "Analyze the provided context.";
    }

    const fullPromptForAI = `${systemContext}\n\nTask: ${aiTask}`;

    this.messages.push({ Role: 'user', Content: userViewMessage });
    this.scrollToBottom();

    const activeId = this.scanId;

    const body = {
      scanReportId: this.isCodeReview ? null : activeId,
      sourceCodeReviewReportId: this.isCodeReview ? activeId : null,
      message: userViewMessage,
      aiPromptContext: fullPromptForAI
    };

    this.chatService.postMessage(body).subscribe({
      next: (res: any) => {
        this.isLoadingResponse = false;
        if (res?.reply || res?.Reply) {
          const aiReply = res.reply || res.Reply;
          const aiExists = this.messages.some(m => m.Content === aiReply);
          if (!aiExists) {
            this.messages.push({ Role: 'assistant', Content: aiReply });
            this.scrollToBottom();
          }
        }
      },
      error: (err) => {
        this.isLoadingResponse = false;
        console.error('Error sending quick action:', err);
      }
    });
  }

  private scrollToBottom(): void {
    if (this.chatMessagesContainer) {
      const element = this.chatMessagesContainer.nativeElement;
      setTimeout(() => {
        element.scrollTop = element.scrollHeight;
      }, 100);
    }
  }

  goBack() {
    if (this.isCodeReview) {
      this.router.navigate(['/source-code-review']);
    } else {
      this.router.navigate(['/dashboard']);
    }
  }

  ngOnDestroy() {
    if (this.messageSub) this.messageSub.unsubscribe();
    if (this.contextSub) this.contextSub.unsubscribe();
  }
}
