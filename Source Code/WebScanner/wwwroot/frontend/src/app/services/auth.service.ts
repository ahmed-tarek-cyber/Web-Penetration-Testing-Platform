import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private apiUrl = 'http://localhost:5000/api/auth';

  // ✅ هذا هو السطر السحري: يحتفظ بحالة المستخدم ويبثها للنافبار
  public currentUser = new BehaviorSubject<string | null>(localStorage.getItem('username'));

  constructor(private http: HttpClient) { }

  register(userData: any): Observable<any> {
    return this.http.post(`${this.apiUrl}/register`, userData);
  }

  login(credentials: any): Observable<any> {
    return this.http.post(`${this.apiUrl}/login`, credentials);
  }

  // ✅ دالة تحديث الحالة (يستخدمها الـ Login)
  notifyLogin(username: string) {
    this.currentUser.next(username);
  }

  // ✅ دالة الخروج (يستخدمها الـ Navbar)
  logout() {
    localStorage.removeItem('authToken');
    localStorage.removeItem('username');
    this.currentUser.next(null); // يبلغ الجميع بالخروج
  }
}
