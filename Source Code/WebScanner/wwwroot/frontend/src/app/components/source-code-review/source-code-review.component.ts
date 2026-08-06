import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { ScanService, SourceCodeReviewReport, SourceCodeReviewReportSummary } from '../../services/scan.service';
import { AiContextService } from '../../services/ai-context.service';

@Component({
  selector: 'app-source-code-review',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './source-code-review.component.html',
  styleUrls: ['./source-code-review.component.css']
})
export class SourceCodeReviewComponent implements OnInit {

  selectedFile: File | null = null;
  latestReport: SourceCodeReviewReport | null = null;
  reports: SourceCodeReviewReportSummary[] = [];
  isScanning = false;
  error: string | null = null;
  successMessage: string | null = null;

  constructor(private scanService: ScanService, private router: Router, private aiContext: AiContextService) {}

  openChatForCode(item: SourceCodeReviewReportSummary) {
    if (!item || !item.reportId) return;

    const findingsCount = item.totalFindings ?? (item as any).total_findings ?? (item as any).TotalFindings ?? 0;

    const context = {
      type: 'code' as const,
      scanId: item.reportId,
      filePath: item.fileName,
      findingsCount: Number(findingsCount) || 0,
      uniqueFindings: []
    };

    this.aiContext.setContext(context);
    this.router.navigate(['/ai', item.reportId], {
      state: {
        data: {
          ...item,
          type: 'code',
          scanId: item.reportId,
          findingsCount: Number(findingsCount) || 0
        }
      }
    });
  }

  ngOnInit(): void {
    const token = localStorage.getItem('authToken');
    if (!token) {
      this.router.navigate(['/login']);
      return;
    }

    this.loadReports();
  }

  onFileSelected(event: Event): void {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0] ?? null;
    this.error = null;
    this.successMessage = null;
    this.latestReport = null;

    if (!file) {
      this.selectedFile = null;
      return;
    }

    const allowed = ['.js', '.html', '.htm'];
    const lowerName = file.name.toLowerCase();
    const isAllowed = allowed.some(ext => lowerName.endsWith(ext));

    if (!isAllowed) {
      this.selectedFile = null;
      this.error = 'Only .js, .html, and .htm files are allowed.';
      input.value = '';
      return;
    }

    if (file.size > 5 * 1024 * 1024) {
      this.selectedFile = null;
      this.error = 'File size must be 5 MB or less.';
      input.value = '';
      return;
    }

    this.selectedFile = file;
  }

  startScan(): void {
    if (!this.selectedFile) {
      this.error = 'Choose a file first.';
      return;
    }

    this.error = null;
    this.successMessage = null;
    this.latestReport = null;
    this.isScanning = true;

    this.scanService.scanSourceCodeFile(this.selectedFile).subscribe({
      next: (report) => {
        this.isScanning = false;
        this.latestReport = report;
        this.successMessage = 'Scan completed successfully.';
        this.selectedFile = null;
        this.loadReports();
      },
      error: (err) => {
        this.isScanning = false;

        if (err?.status === 401) {
          localStorage.removeItem('authToken');
          localStorage.removeItem('username');
          this.router.navigate(['/login']);
          return;
        }

        this.error = err?.error?.error || 'Scan failed. Please try again.';
      }
    });
  }

  viewReport(report: SourceCodeReviewReportSummary): void {
    if (!report.downloadUrl) return;
    window.open(`${report.downloadUrl}`, '_blank', 'noopener,noreferrer');
  }

  downloadReport(report: SourceCodeReviewReportSummary): void {
    if (!report.reportId) return;

    this.scanService.downloadSourceCodeReviewReport(report.reportId).subscribe({
      next: (response: Blob) => {
        const filename = `SphinxEye_Source_Review_${report.fileName || report.reportId}.html`;
        const blob = new Blob([response], { type: 'text/html' });
        const url = window.URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = filename;
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
        window.URL.revokeObjectURL(url);
      },
      error: () => {
        this.error = 'Failed to download report.';
      }
    });
  }

  clearSelection(): void {
    this.selectedFile = null;
    this.error = null;
    this.latestReport = null;
    this.successMessage = null;
  }

  deleteReport(report: SourceCodeReviewReportSummary): void {
    if (!report.reportId) return;

    if (!confirm('Delete this source review report permanently?')) {
      return;
    }

    this.scanService.deleteSourceCodeReviewReport(report.reportId).subscribe({
      next: () => {
        this.reports = this.reports.filter(item => item.reportId !== report.reportId);
      },
      error: () => {
        this.error = 'Failed to delete report.';
      }
    });
  }

  private loadReports(): void {
    this.scanService.getSourceCodeReviewReports().subscribe({
      next: (data) => {
        this.reports = (data || []).map((item: any) => ({
          ...item,
          reportId: item.reportId || item.ReportId,
          fileName: item.fileName || item.FileName,
          createdAt: item.createdAt || item.CreatedAt,
          completedAt: item.completedAt || item.CompletedAt,
          status: item.status || item.Status,
          overallStatus: item.overallStatus || item.overall_status || item.OverallStatus,
          totalFindings: item.totalFindings ?? item.total_findings ?? item.TotalFindings ?? 0,
          severityBreakdown: item.severityBreakdown || item.severity_breakdown || item.SeverityBreakdown,
          downloadUrl: item.downloadUrl || item.DownloadUrl
        }));
      },
      error: () => {
        this.error = 'Failed to load saved source review reports.';
      }
    });
  }

  get latestStatus(): string {
    return this.isScanning ? 'Scanning...' : (this.reports[0]?.overallStatus || this.latestReport?.overall_status || 'Ready to review');
  }
}
