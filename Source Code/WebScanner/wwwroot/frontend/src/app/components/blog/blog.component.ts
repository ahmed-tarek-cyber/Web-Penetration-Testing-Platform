import { Component, ElementRef, AfterViewInit } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-blog',
  standalone: true, // تأكيد إن المكون Standalone زي الـ Home عشان التوافق
  imports: [CommonModule],
  templateUrl: './blog.component.html',
  styleUrls: ['./blog.component.css']
})
export class BlogComponent implements AfterViewInit {
  // مصفوفة التحكم في فتح وإغلاق كروت المقالات الثلاثة
  expanded: boolean[] = [false, false, false]; 

  constructor(private el: ElementRef) {}

  // دالة تبديل حالة الكارت (إظهار المزيد / إخفاء)
  toggleExpand(index: number) {
    this.expanded[index] = !this.expanded[index];
  }

  // تشغيل تأثير الـ Fade-In التدريجي عند ظهور السكشن على الشاشة
  ngAfterViewInit() {
    const elements = this.el.nativeElement.querySelectorAll('.fade-up');
    
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry, index) => {
          if (entry.isIntersecting) {
            // إضافة كلاس 'show' بتأثير تدريجي (Staggered Animation) بناءً على ترتيب الكارت
            setTimeout(() => entry.target.classList.add('show'), index * 150);
          } else {
            // إزالة الكلاس عند الخروج من الشاشة لإعادة الأنميشن مرة أخرى
            entry.target.classList.remove('show');
          }
        });
      },
      { threshold: 0.1 } // تقليل الـ threshold لـ 0.1 عشان الأنميشن يلقط أسرع على الشاشات الصغيرة
    );

    elements.forEach((el: Element) => observer.observe(el));
  }
}