import { Component, Input, OnChanges, SimpleChanges } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ScanService, ScanResult, ScanIssue } from '../../services/scan.service';

@Component({
  selector: 'app-search-result',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './search-result.component.html',
  styleUrls: ['./search-result.component.css']
})
export class SearchResultComponent implements OnChanges {
  @Input() data!: ScanResult;
  uniqueIssues: string[] = []; // قائمة أسماء فقط

  constructor(private scanService: ScanService) { }

  ngOnChanges(changes: SimpleChanges): void {
    if (this.data && this.data.Issues) {
      // استخراج الأسماء الفريدة فقط (بدون تكرار)
      this.uniqueIssues = Array.from(new Set(this.data.Issues.map(i => i.Name)));
    }
  }

  downloadFullReport() {
    if (!this.data?.ReportId) return;

    this.scanService.downloadReport(this.data.ReportId).subscribe({
      next: (blob) => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `Report-${new Date().getTime()}.txt`;
        a.click();
        window.URL.revokeObjectURL(url);
      },
      error: (err) => console.error('Download failed', err)
    });
  }
}
