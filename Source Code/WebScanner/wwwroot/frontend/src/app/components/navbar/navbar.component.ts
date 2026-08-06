import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule, Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import { Subscription } from 'rxjs';

@Component({
  selector: 'app-navbar',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './navbar.component.html',
  styleUrls: ['./navbar.component.css']
})
export class NavbarComponent implements OnInit, OnDestroy {
  username: string | null = null;
  private userSub!: Subscription; // متغير لحفظ الاشتراك وإلغائه لاحقاً

  constructor(public authService: AuthService, private router: Router) { }

  ngOnInit() {
    // ✅ الاشتراك في البث المباشر: أي تغيير في حالة المستخدم هيسمع هنا فوراً
    this.userSub = this.authService.currentUser.subscribe({
      next: (name) => {
        this.username = name;
      },
      error: (err) => {
        console.error('Navbar Auth Subscription Error:', err);
      }
    });
  }

  // دالة تسجيل الخروج وتوجيه المستخدم
  onLogout() {
    this.authService.logout();
    this.router.navigate(['/login']);
  }

  // تنظيف الـ Subscription عند إغلاق أو تدمير المكون لمنع الـ Memory Leaks
  ngOnDestroy() {
    if (this.userSub) {
      this.userSub.unsubscribe();
    }
  }
}