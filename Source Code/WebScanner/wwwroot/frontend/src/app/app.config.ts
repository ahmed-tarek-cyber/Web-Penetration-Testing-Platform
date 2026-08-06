import { ApplicationConfig } from '@angular/core';
import { provideRouter } from '@angular/router';
import { routes } from './app.routes';
// 👇 1. استيراد الدوال دي
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { importProvidersFrom } from '@angular/core';
import { ReactiveFormsModule, FormsModule } from '@angular/forms';

// 👇 2. استيراد الـ Interceptor بتاعنا
import { authInterceptor } from './interceptors/auth.interceptor';

export const appConfig: ApplicationConfig = {
  providers: [
    provideRouter(routes),

    // 👇👇 3. ده السطر السحري اللي كان ناقص أو مكتوب غلط 👇👇
    provideHttpClient(withInterceptors([authInterceptor])),

    importProvidersFrom(ReactiveFormsModule, FormsModule)
  ]
};
