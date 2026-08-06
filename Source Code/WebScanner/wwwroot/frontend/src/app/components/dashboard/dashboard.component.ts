import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ScanService } from '../../services/scan.service';
import { Router } from '@angular/router';
import { AiContextService } from '../../services/ai-context.service';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.css']
})
export class DashboardComponent implements OnInit {
  reports: any[] = [];
  isLoading = true;

  // متغيرات النافذة المنبثقة
  showModal: boolean = false;
  uniqueVulnNames: string[] = []; // لتخزين الأسماء الفريدة
  isLoadingDetails: boolean = false;

  constructor(private scanService: ScanService, private router: Router, private aiContext: AiContextService) { }

  openChat(report: any) {
    const id = report.Id || report.id;
    if (!id) return;

    const findingsCount = report.TotalCount || report.totalCount || report.TotalFindings || report.totalFindings || 0;

    this.aiContext.setContext({
      type: 'web',
      scanId: String(id),
      findingsCount: Number(findingsCount) || 0,
      uniqueFindings: []
    });

    this.router.navigate(['/ai', id], {
      state: {
        data: {
          ...report,
          type: 'web',
          scanId: String(id),
          findingsCount: Number(findingsCount) || 0
        }
      }
    });
  }

  ngOnInit() {
    this.loadReports();
  }

  loadReports() {
    this.scanService.getReports().subscribe({
      next: (data) => {
        this.reports = data;
        this.isLoading = false;
      },
      error: (err) => { console.error(err); this.isLoading = false; }
    });
  }

  // ✅ دالة زر View: تجلب البيانات وتعرض الأسماء فقط
  viewReport(report: any) {
    this.showModal = true;
    this.isLoadingDetails = true;
    this.uniqueVulnNames = []; // تصفير القائمة القديمة

    const id = report.Id || report.id;

    this.scanService.getVulnerabilities(id).subscribe({
      next: (res) => {
        // 1. استلام البيانات (نتأكد من حالة الحروف Data او data)
        const allVulns = res.Data || res.data || [];

        // 2. استخراج الاسم فقط (Name)
        const names = allVulns.map((v: any) => v.Name || v.name);

        // 3. إزالة التكرار باستخدام Set
        this.uniqueVulnNames = [...new Set(names) as Set<string>];

        this.isLoadingDetails = false;
      },
      error: (err) => {
        console.error(err);
        this.isLoadingDetails = false;
      }
    });
  }

  // 🔥 دالة تحميل التقرير (تم التعديل لطلب الملف بـ Blob) 🔥
  downloadReport(id: string) {
    if (!id) return;

    // نستخدم الـ Service لجلب الملف كـ Blob، والتي سترسل التوكن تلقائياً
    this.scanService.downloadReport(id).subscribe({
      next: (response: Blob) => {
        // منطق حفظ الملف في المتصفح
        const filename = `SphinxEye_Report_${id}.html`;

        // 1. إنشاء كائن Blob من الرد (المحتوى هو HTML)
        const blob = new Blob([response], { type: 'text/html' });

        // 2. إنشاء رابط وهمي (Object URL)
        const url = window.URL.createObjectURL(blob);

        // 3. إنشاء عنصر <a> والنقر عليه آلياً لتشغيل التحميل
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();

        // 4. تنظيف الرابط وعنصر <a>
        window.URL.revokeObjectURL(url);
        a.remove();
      },
      error: (err) => {
        console.error('Download Error:', err);
        alert('Download failed: Authentication error (401) or file not found.');
      }
    });
  }

  // دالة الحذف
  deleteReport(id: string) {
    // 1. رسالة تأكيد (Safety Check)
    if (!confirm('Are you sure you want to delete this scan permanently?')) {
      return;
    }

    // 2. استدعاء السيرفس للحذف
    this.scanService.deleteReport(id).subscribe({
      next: () => {
        // 3. تحديث الجدول فوراً بحذف العنصر من المصفوفة
        this.reports = this.reports.filter(r => (r.Id || r.id) !== id);
        alert('Scan deleted successfully.');
      },
      error: (err) => {
        console.error(err);
        alert('Failed to delete scan.');
      }
    });
  }

  // دالة إغلاق النافذة المنبثقة
  closeModal() {
    this.showModal = false;
    this.uniqueVulnNames = [];
  }
}
