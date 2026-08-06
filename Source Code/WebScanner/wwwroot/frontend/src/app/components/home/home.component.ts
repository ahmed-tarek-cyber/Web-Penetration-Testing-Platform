import { Component, AfterViewInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { ScanService } from '../../services/scan.service';

@Component({
  selector: 'app-home',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.css']
})
export class HomeComponent implements AfterViewInit, OnDestroy {
  query: string = '';
  searching = false;
  error: string | null = null;
  private animationId: number | null = null;

  // متغيرات لتتبع الماوس
  private mouseX: number = 0;
  private mouseY: number = 0;

  constructor(private scanService: ScanService, private router: Router) { }

  onSearch() {
    const token = localStorage.getItem('authToken');

    if (!token) {
      this.router.navigate(['/login']);
      return;
    }

    this.error = null;
    const q = this.query.trim();

    if (!q) {
      this.error = 'Please enter a URL or domain.';
      return;
    }

    this.searching = true;

    this.scanService.scan(q).subscribe({
      next: (res: any) => {
        this.searching = false;
        const id = res.reportId || res.ReportId;

        if (id) {
          this.router.navigate(['/dashboard']);
        } else {
          this.error = 'Scan finished but no Report ID returned.';
        }
      },
      error: (err) => {
        this.searching = false;
        console.error('Scan Error:', err);

        if (err.status === 401) {
          localStorage.removeItem('authToken');
          localStorage.removeItem('username');
          this.router.navigate(['/login']);
        } else {
          this.error = 'Scan failed. Please check the backend connection.';
        }
      }
    });
  }

  // دالة تتبع حركة الماوس
  onMouseMove(event: MouseEvent) {
    this.mouseX = event.clientX;
    this.mouseY = event.clientY;
  }

  ngAfterViewInit() {
    this.initVortexEffect();
    window.addEventListener('resize', this.onResize);
    // تفعيل مستمع الماوس على الـ window لضمان التتبع السلس
    window.addEventListener('mousemove', (e) => this.onMouseMove(e));
  }

  ngOnDestroy() {
    if (this.animationId) cancelAnimationFrame(this.animationId);
    window.removeEventListener('resize', this.onResize);
    window.removeEventListener('mousemove', (e) => this.onMouseMove(e));
  }

  onResize = () => {
    if (this.animationId) cancelAnimationFrame(this.animationId);
    this.initVortexEffect();
  }

  private initVortexEffect() {
    const canvas = document.getElementById('spider-bg') as HTMLCanvasElement;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    let particles: any[] = [];
    const particleCount = 150; // زودنا العدد لـ 150 عشان الدوامة تظهر غنية ومثالية
    const purpleColor = '168, 85, 247'; // اللون البنفسجي النيون الخاص بـ SphinxEye
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;

    // إنشاء جزيئات بمسارات دائرية حول المركز
    for (let i = 0; i < particleCount; i++) {
      const angle = Math.random() * Math.PI * 2;
      const radius = Math.random() * (canvas.width / 1.5);
      particles.push({
        angle: angle,
        radius: radius,
        speed: 0.002 + Math.random() * 0.004, // سرعة الدوران الحلزوني
        size: 1 + Math.random() * 1.5,
        pulse: Math.random() * Math.PI
      });
    }

    const animate = () => {
      // تعديل مسح الخلفية للحفاظ على درجة الداكنة للفوتر وعمل تأثير ذيل (Trails) خلف النقط
      ctx.fillStyle = 'rgba(11, 5, 24, 0.15)';
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      for (let i = 0; i < particles.length; i++) {
        let p = particles[i];

        // 1. تحديث زاوية الدوران الحلزوني
        p.angle += p.speed;
        
        // 2. سحب تدريجي ناعم نحو المركز لعمل تأثير الدوامة
        p.radius -= 0.3; 
        if (p.radius <= 0) {
          p.radius = (canvas.width / 1.5) + Math.random() * 50; 
          p.angle = Math.random() * Math.PI * 2;
        }

        // 3. تحويل الإحداثيات القطبية إلى ديكارتية لرسمها على الـ Canvas
        const x = centerX + Math.cos(p.angle) * p.radius;
        const y = centerY + Math.sin(p.angle) * p.radius;

        // 4. تأثير النبض المتوهج (Glow Effect) على الشفافية
        p.pulse += 0.03;
        const opacity = 0.4 + Math.abs(Math.sin(p.pulse)) * 0.5;

        // 5. رسم الجسيم البنفسجي
        ctx.beginPath();
        ctx.arc(x, y, p.size, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${purpleColor}, ${opacity})`;
        ctx.fill();

        // 6. تفاعل الماوس (خطوط ليزر نيون خفيفة عند اقتراب المؤشر)
        let distToMouse = Math.hypot(x - this.mouseX, y - this.mouseY);
        if (distToMouse < 150) {
          ctx.strokeStyle = `rgba(${purpleColor}, ${0.5 * (1 - distToMouse / 150)})`;
          ctx.lineWidth = 0.5;
          ctx.beginPath();
          ctx.moveTo(x, y);
          ctx.lineTo(this.mouseX, this.mouseY);
          ctx.stroke();
        }
      }
      this.animationId = requestAnimationFrame(animate);
    };

    animate();
  }
}