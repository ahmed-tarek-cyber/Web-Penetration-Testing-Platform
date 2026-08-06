import { Component } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { CommonModule } from '@angular/common';
import { NavigationEnd, Router } from '@angular/router';
import { NavbarComponent } from './components/navbar/navbar.component';
import { FooterComponent } from './components/footer/footer.component';
import { BlogComponent } from './components/blog/blog.component';
import { filter } from 'rxjs/operators';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, RouterOutlet, NavbarComponent, FooterComponent, BlogComponent],
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent {
  showGlobalSections = true;

  constructor(private router: Router) {
    this.updateGlobalSectionsVisibility(this.router.url);

    this.router.events
      .pipe(filter((event) => event instanceof NavigationEnd))
      .subscribe((event) => {
        const nav = event as NavigationEnd;
        this.updateGlobalSectionsVisibility(nav.urlAfterRedirects);
      });
  }

  private updateGlobalSectionsVisibility(url: string): void {
    // Hide global sections (About/Blog) on Source Code Review, Dashboard and About pages
    this.showGlobalSections = !(url.startsWith('/source-code-review') || url.startsWith('/dashboard') || url.startsWith('/about') || url.startsWith('/ai'));
  }
}
