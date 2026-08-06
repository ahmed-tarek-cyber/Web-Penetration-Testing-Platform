export interface ChatContext {
  type: 'code' | 'web';
  scanId: string;
  filePath?: string;
  codeSnippet?: string;
  vulnerabilityName?: string;
  findingsCount?: number;
  uniqueFindings?: any[];
}
