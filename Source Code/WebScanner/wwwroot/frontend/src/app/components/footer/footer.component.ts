import { Component } from '@angular/core';
import { RouterModule } from '@angular/router';

@Component({
  selector: 'app-footer',
  standalone: true,
  imports: [RouterModule],
  templateUrl: './footer.component.html',
  styleUrls: ['./footer.component.css']
})
export class FooterComponent {

  // الدالة السحرية اللي الـ HTML بيدور عليها
  scrollToTop(): void {
    // تجربة صعود المتصفح الأساسي
    window.scrollTo({ top: 0, behavior: 'smooth' });

    // تجربة صعود الـ body والـ html
    document.body.scrollTo({ top: 0, behavior: 'smooth' });
    document.documentElement.scrollTo({ top: 0, behavior: 'smooth' });

    // استهداف حاوية المحتوى الرئيسية في الأنجيلور لو واخدة السكرول
    const mainContent = document.querySelector('.main-content');
    if (mainContent) {
      mainContent.scrollTo({ top: 0, behavior: 'smooth' });
    }
  }
}