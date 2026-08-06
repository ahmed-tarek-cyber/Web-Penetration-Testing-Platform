import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, RouterModule } from '@angular/router'; // ✅ إضافة RouterModule
import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'app-register',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterModule], // ✅ إضافة RouterModule هنا
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.css']
})
export class RegisterComponent {
  username = ''; // ✅ تغيير Name إلى Username ليطابق الباك إند
  email = '';
  password = '';
  confirmPassword = '';
  inviteCode = ''; // ✅ المتغير الجديد لكود الدعوة

  message: string | null = null;
  errorMessage: string | null = null;
  loading = false;

  constructor(private router: Router, private authService: AuthService) { }

  onSubmit() {
    // ✅ التحقق من المدخلات (شامل كود الدعوة)
    if (!this.username || !this.email || !this.password || !this.confirmPassword || !this.inviteCode) {
      this.errorMessage = '⚠️ Please fill in all fields (including Invite Code).';
      this.message = null;
      return;
    }

    if (this.password !== this.confirmPassword) {
      this.errorMessage = '⚠️ Passwords do not match.';
      this.message = null;
      return;
    }

    this.loading = true;
    this.errorMessage = null;
    this.message = null;

    // ✅ تجهيز بيانات المستخدم (نفس أسماء RegisterRequest في C#)
    const userData = {
      username: this.username,
      email: this.email,
      password: this.password,
      inviteCode: this.inviteCode // ✅ إرسال كود الدعوة
    };

    // ✅ استدعاء API
    this.authService.register(userData).subscribe({
      next: (res) => {
        this.loading = false;
        this.message = '✅ Registration successful! Redirecting...'; // رسالة نجاح
        this.errorMessage = null;

        // ✅ الانتقال لصفحة تسجيل الدخول
        setTimeout(() => {
          this.router.navigate(['/login']);
        }, 1500);
      },
      error: (err) => {
        this.loading = false;
        console.error('Registration error:', err);
        // عرض الرسالة القادمة من الباك إند (مثل Invalid Invitation Code)
        this.errorMessage =
          err.error?.message || '❌ Registration failed. Please check your code.';
        this.message = null;
      }
    });
  }
}
