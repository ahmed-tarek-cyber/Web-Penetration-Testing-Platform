import { Component, OnInit, ViewChild, ElementRef } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { CommonModule } from '@angular/common'; // ✅ هام جداً
import { ScanService } from '../../services/scan.service';
import { Chart, registerables } from 'chart.js';

Chart.register(...registerables);

@Component({
  selector: 'app-report-view',
  standalone: true, // ✅ تفعيل الـ Standalone
  imports: [CommonModule], // ✅ استيراد الأدوات الأساسية
  templateUrl: './report-view.component.html',
  styleUrls: ['./report-view.component.css']
})
export class ReportViewComponent implements OnInit {
  @ViewChild('pieCanvas') pieCanvas!: ElementRef;

  vulns: any[] = [];
  stats: any = {};
  reportId: string = '';
  chart: any;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private scanService: ScanService
  ) { }

  ngOnInit() {
    this.reportId = this.route.snapshot.paramMap.get('id') || '';

    this.scanService.getStats(this.reportId).subscribe(data => {
      this.stats = data;
      setTimeout(() => this.renderChart(), 100);
    });

    this.scanService.getVulnerabilities(this.reportId).subscribe(res => {
      this.vulns = res.data;
    });
  }

  renderChart() {
    if (this.chart) this.chart.destroy();

    // تأكد أن الكانفاس موجود قبل الرسم
    if (!this.pieCanvas?.nativeElement) return;

    this.chart = new Chart(this.pieCanvas.nativeElement, {
      type: 'doughnut',
      data: {
        labels: ['High', 'Medium', 'Low'],
        datasets: [{
          data: [this.stats.high, this.stats.medium, this.stats.low],
          backgroundColor: ['#dc3545', '#ffc107', '#28a745']
        }]
      },
      options: {
        responsive: true,
        plugins: { legend: { position: 'bottom' } }
      }
    });
  }

  goBack() {
    this.router.navigate(['/dashboard']);
  }
}
