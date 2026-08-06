import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';

export interface SourceCodeReviewFinding {
  vuln_id: string;
  name: string;
  severity: string;
  file: string;
  line: number;
  match: string;
  context: string;
}

export interface SourceCodeReviewReport {
  reportId?: string;
  fileName?: string;
  createdAt?: string;
  completedAt?: string;
  engine: string;
  status: string;
  file: string;
  file_size: number;
  overall_status: string;
  total_findings: number;
  severity_breakdown: {
    Critical: number;
    High: number;
    Medium: number;
    Low: number;
    Info: number;
  };
  findings: SourceCodeReviewFinding[];
  downloadUrl?: string;
}

export interface SourceCodeReviewReportSummary {
  reportId: string;
  fileName: string;
  createdAt: string;
  completedAt?: string;
  status: string;
  overallStatus: string;
  totalFindings: number;
  severityBreakdown: {
    Critical: number;
    High: number;
    Medium: number;
    Low: number;
    Info: number;
  };
  downloadUrl: string;
}

export interface ScanResult {
  ReportId: string;
  Url: string;
  Status: string;
  AiSummary: string;
  Issues: ScanIssue[];
  CompletedAt: string;
  Duration: number;
}

export interface ScanIssue {
  Name: string;
  Severity: string;
  Description: string;
  Location: string;
  Color: string;
  Payload?: string;
}

@Injectable({
  providedIn: 'root'
})
export class ScanService {
  // رابط الـ Scan Controller (للتشغيل)
  private apiBase = `${environment.apiUrl}/scan`;

  // ✅ رابط الـ Reports Controller (للتقارير والداشبورد)
  private reportsApi = `${environment.apiUrl}/reports`;

  // رابط فحص السورس كود الجديد
  private sourceCodeReviewApi = `${environment.apiUrl}/source-code-review`;

  constructor(private http: HttpClient) { }

  // 1. تشغيل الفحص
  scan(query: string): Observable<ScanResult> {
    const payload = { url: query };
    return this.http.post<ScanResult>(`${this.apiBase}/run`, payload);
  }

  scanSourceCodeFile(file: File): Observable<SourceCodeReviewReport> {
    const formData = new FormData();
    formData.append('file', file, file.name);
    return this.http.post<SourceCodeReviewReport>(`${this.sourceCodeReviewApi}/scan`, formData);
  }

  getSourceCodeReviewReports(): Observable<SourceCodeReviewReportSummary[]> {
    return this.http.get<SourceCodeReviewReportSummary[]>(`${this.sourceCodeReviewApi}/reports`);
  }

  downloadSourceCodeReviewReport(reportId: string): Observable<Blob> {
    return this.http.get(`${this.sourceCodeReviewApi}/reports/${reportId}/download`, { responseType: 'blob' });
  }

  deleteSourceCodeReviewReport(reportId: string): Observable<any> {
    return this.http.delete(`${this.sourceCodeReviewApi}/reports/${reportId}`);
  }

  // 7. دالة الحذف
  deleteReport(id: string): Observable<any> {
    return this.http.delete(`${this.reportsApi}/${id}`);
  }

  // 🔥 2. تحميل التقرير كملف (Blob) - الحل لمشكلة 401 🔥
  downloadReport(reportId: string): Observable<Blob> {
    // responseType: 'blob' يضمن أن Angular يتوقع بيانات ثنائية
    return this.http.get(`${this.reportsApi}/${reportId}/download`, { responseType: 'blob' });
  }

  // =========================================================
  // ✅ الإضافات الأخرى
  // =========================================================

  // 3. جلب قائمة التقارير السابقة (للجدول في Dashboard)
  getReports(): Observable<any[]> {
    return this.http.get<any[]>(this.reportsApi);
  }

  // 4. جلب إحصائيات تقرير معين
  getStats(id: string): Observable<any> {
    return this.http.get<any>(`${this.reportsApi}/${id}/stats`);
  }

  // 5. جلب الثغرات مقسمة صفحات
  getVulnerabilities(id: string, page: number = 1, pageSize: number = 10): Observable<any> {
    return this.http.get<any>(`${this.reportsApi}/${id}/vulnerabilities?page=${page}&pageSize=${pageSize}`);
  }
  // جوه ملف scan.service.ts

  // ميثود بتجيب بيانات فحص معين (URL, التاريخ، الحالة)
  getScanDetails(id: number | string): Observable<any> {
    // تأكد إن الرابط ده موجود عندك في الباك-إند وبيرجع بيانات الـ Scan
    return this.http.get(`http://localhost:5000/api/scan/${id}`);
  }
}
