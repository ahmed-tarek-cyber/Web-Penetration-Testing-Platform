import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent {
  email = '';
  password = '';
  loading = false;

  message: string | null = null;
  errorMessage: string | null = null;

  constructor(private router: Router, private authService: AuthService) { }

  onSubmit() {
    this.message = null;
    this.errorMessage = null;

    if (!this.email || !this.password) {
      this.errorMessage = '⚠️ Please fill in all fields.';
      return;
    }

    const credentials = { email: this.email, password: this.password };
    this.loading = true;

    this.authService.login(credentials).subscribe({
      next: (res: any) => {
        this.loading = false;
        this.message = '✅ Login successful!';

        // فحص التوكن بالحروف الكبيرة أو الصغيرة لضمان قراءته من الـ API
        const token = res.Token || res.token;

        if (token) {
          localStorage.setItem('authToken', token);

          // حفظ اسم المستخدم أو قطع الإيميل كاسم بديل
          const user = res.Username || res.username || this.email.split('@')[0];
          localStorage.setItem('username', user);

          // تبليغ الـ Navbar بتحديث حالة تسجيل الدخول فوراً
          this.authService.notifyLogin(user);

          // توجيه المستخدم للصفحة الرئيسية بعد ثانية واحدة للاستمتاع بالأنميشن
          setTimeout(() => {
            this.router.navigate(['/']);
          }, 1000);
        } else {
          console.error("Login Success but Token is missing in response:", res);
          this.errorMessage = 'Login succeeded but system failed to save session.';
        }
      },
      error: (err) => {
        this.loading = false;
        console.error(err);
        this.errorMessage = err.error?.message || '❌ Invalid Email or Password';
      }
    });
  }

  // الانتقال لصفحة إنشاء حساب جديد
  goToRegister() {
    this.router.navigate(['/register']);
  }
}