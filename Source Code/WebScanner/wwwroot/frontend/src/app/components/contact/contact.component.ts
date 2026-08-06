// import { Component } from '@angular/core';
// import { FormBuilder, FormGroup,ReactiveFormsModule, Validators } from '@angular/forms';
// import { HttpClient } from '@angular/common/http';

// @Component({
//   selector: 'app-contact',
//   imports: [ ReactiveFormsModule],
//   templateUrl: './contact.component.html',
//   styleUrls: ['./contact.component.css']
// })
// export class ContactComponent {
//   contactForm: FormGroup;
//   isLoading = false;

//   constructor(private fb: FormBuilder, private http: HttpClient) {
//     this.contactForm = this.fb.group({
//       name: ['', Validators.required],
//       email: ['', [Validators.required, Validators.email]],
//       message: ['', Validators.required]
//     });
//   }

//   onSubmit() {
//     if (this.contactForm.invalid) {
//       alert('Please fill all required fields.');
//       return;
//     }

//     this.isLoading = true;

//     const formData = this.contactForm.value;

//     // 🔹 هنا بتحط لينك الـ API بتاع الـ Backend الحقيقي
//     this.http.post('http://localhost:5000/api/contact', formData).subscribe({
//       next: (res) => {
//         alert('✅ Message sent successfully!');
//         this.contactForm.reset();
//         this.isLoading = false;
//       },
//       error: (err) => {
//         console.error(err);
//         alert('❌ Error sending message.');
//         this.isLoading = false;
//       }
//     });
//   }
// }
import { Component } from '@angular/core';
import { FormBuilder, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { ContactService } from '../../services/contact.service';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-contact',
  standalone: true,
  imports: [ReactiveFormsModule, CommonModule],
  templateUrl: './contact.component.html',
  styleUrls: ['./contact.component.css']
})
export class ContactComponent {
  contactForm: FormGroup;
  isLoading = false;
  successMessage: string | null = null;
  errorMessage: string | null = null;

  constructor(private fb: FormBuilder, private contactService: ContactService) {
    this.contactForm = this.fb.group({
      name: ['', Validators.required],
      email: ['', [Validators.required, Validators.email]],
      message: ['', Validators.required]
    });
  }

  onSubmit() {
    // ✅ التحقق من صحة البيانات
    if (this.contactForm.invalid) {
      this.errorMessage = '⚠️ Please fill all required fields correctly.';
      this.successMessage = null;
      return;
    }

    this.isLoading = true;
    this.successMessage = null;
    this.errorMessage = null;

    const formData = this.contactForm.value;

    // ✅ إرسال البيانات للباك إند
    this.contactService.sendMessage(formData).subscribe({
      next: () => {
        this.successMessage = '✅ Message sent successfully! We’ll get back to you soon.';
        this.errorMessage = null;
        this.contactForm.reset();
        this.isLoading = false;
      },
      error: (err) => {
        console.error(err);
        this.errorMessage = '❌ Failed to send message. Please try again later.';
        this.successMessage = null;
        this.isLoading = false;
      }
    });
  }
}
