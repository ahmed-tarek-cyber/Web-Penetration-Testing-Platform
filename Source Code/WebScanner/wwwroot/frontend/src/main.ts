import { bootstrapApplication } from '@angular/platform-browser';
import { AppComponent } from './app/app.component';
// 👇 1. استدعاء ملف الإعدادات (المهم جداً)
import { appConfig } from './app/app.config';

// 👇 2. تمرير appConfig هنا هو ما يفعل الإنترسبتور
bootstrapApplication(AppComponent, appConfig)
  .catch((err) => console.error(err));
