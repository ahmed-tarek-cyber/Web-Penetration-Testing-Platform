import { HttpInterceptorFn } from '@angular/common/http';

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  // 1. البحث عن التوكن
  const token = localStorage.getItem('authToken');

  // 👇👇 رسائل المراقبة (ستظهر في الكونسول) 👇👇
  console.log('🛑 Interceptor Triggered for URL:', req.url);
  console.log('🔑 Token found in storage?', token ? 'YES' : 'NO');

  if (token) {
    console.log('✅ Attaching Token to Header...');
    const clonedRequest = req.clone({
      setHeaders: {
        Authorization: `Bearer ${token}`
      }
    });
    return next(clonedRequest);
  }

  console.warn('⚠️ No Token found! Request sent without Auth.');
  return next(req);
};
