import { Routes } from '@angular/router';

// المكونات الموجودة سابقاً
import { HomeComponent } from './components/home/home.component';
import { LoginComponent } from './components/login/login.component';
import { RegisterComponent } from './components/register/register.component';
import { ContactComponent } from './components/contact/contact.component';
import { AboutComponent } from './components/about/about.component';

// ✅ المكونات الجديدة (تأكد أنك أنشأتها في هذه المسارات)
import { DashboardComponent } from './components/dashboard/dashboard.component';
import { ReportViewComponent } from './components/report-view/report-view.component';
import { SourceCodeReviewComponent } from './components/source-code-review/source-code-review.component';
//ai chat
import { AiAssistantComponent } from './components/pages/ai-assistant/ai-assistant.component';

export const routes: Routes = [
  { path: '', component: HomeComponent },
  { path: 'login', component: LoginComponent },
  { path: 'register', component: RegisterComponent },
  { path: 'contact', component: ContactComponent },
  { path: 'about', component: AboutComponent },

  // ✅ المسارات الجديدة المضافة
  { path: 'dashboard', component: DashboardComponent },
  { path: 'source-code-review', component: SourceCodeReviewComponent },
  //ai chat
  { path: 'ai/:id', component: AiAssistantComponent },
 // { path: 'report/:id', component: ReportViewComponent }, // :id تعني أن الرابط يقبل متغير

  { path: '**', redirectTo: '' }
];
