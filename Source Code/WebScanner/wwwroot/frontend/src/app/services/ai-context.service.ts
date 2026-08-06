import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

export interface ChatContext {
  type: 'code' | 'web';
  scanId: string;
  filePath?: string;
  codeSnippet?: string;
  vulnerabilityName?: string;
  findingsCount?: number;
  uniqueFindings?: any[];
}

@Injectable({
  providedIn: 'root'
})
export class AiContextService {
  private chatContextSubject = new BehaviorSubject<ChatContext | null>(null);

  setContext(context: ChatContext) {
    this.chatContextSubject.next(context);
  }

  getContextValue(): ChatContext | null {
    return this.chatContextSubject.value;
  }

  clearContext() {
    this.chatContextSubject.next(null);
  }
}
