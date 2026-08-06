import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';

// تعريف Interface بسيط لضمان الـ Type Safety للكروت ومنع أي تضارب
interface AboutCard {
  title: string;
  summary: string;
  details: string[];
  expanded: boolean;
}

@Component({
  selector: 'app-about',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './about.component.html',
  styleUrls: ['./about.component.css']
})
export class AboutComponent {
  reconCards: AboutCard[] = [
    {
      title: 'Surface Mapping',
      summary: 'Collect domains, subdomains, open ports, and exposed services to build the full attack surface.',
      details: [
        'Find active hosts and map how they are connected to your main target.',
        'Identify internet-facing services that can be tested next.',
        'Highlight forgotten or shadow assets that often get missed in manual checks.'
      ],
      expanded: false
    },
    {
      title: 'Technology Fingerprinting',
      summary: 'Detect frameworks, server stacks, and components that may have known weaknesses.',
      details: [
        'Recognize web technologies and software versions when possible.',
        'Prioritize checks based on likely risk for each detected technology.',
        'Guide the scanner toward tests that match the target tech stack.'
      ],
      expanded: false
    },
    {
      title: 'Endpoint Discovery',
      summary: 'Enumerate reachable paths, parameters, and files that could expose risky functionality.',
      details: [
        'Discover hidden paths and inputs that are not obvious from the homepage.',
        'Track query/body parameters that are good candidates for security testing.',
        'Feed discovered endpoints into vulnerability-specific checks.'
      ],
      expanded: false
    }
  ];

  vulnerabilityCards: AboutCard[] = [
    {
      title: 'SQL Injection',
      summary: 'Untrusted input reaches database queries and can alter SQL logic.',
      details: [
        'May allow unauthorized data reading or modification.',
        'Can bypass authentication in poorly protected flows.',
        'Typical mitigations: parameterized queries and strict input validation.'
      ],
      expanded: false
    },
    {
      title: 'Cross-Site Scripting (XSS)',
      summary: 'Attacker-controlled script runs in the victim browser.',
      details: [
        'Can steal sessions, modify page content, or trigger unwanted actions.',
        'Often appears when output encoding is missing in dynamic views.',
        'Typical mitigations: contextual encoding, CSP, and sanitization.'
      ],
      expanded: false
    },
    {
      title: 'NoSQL Injection',
      summary: 'User input manipulates NoSQL queries and bypasses intended filtering logic.',
      details: [
        'Can expose or modify records without proper authorization.',
        'Often appears when dynamic query objects are built from raw input.',
        'Typical mitigations: strict schema validation and safe query construction.'
      ],
      expanded: false
    },
    {
      title: 'IDOR',
      summary: 'Direct object references are exposed without proper authorization checks.',
      details: [
        'Attackers can access or modify other users data by changing identifiers.',
        'Common on APIs that trust client-provided IDs.',
        'Typical mitigations: server-side ownership checks and indirect references.'
      ],
      expanded: false
    },
    {
      title: 'Directory Traversal',
      summary: 'Path handling is unsafe, allowing access to files outside intended directories.',
      details: [
        'Attackers use sequences like ../ to reach restricted files.',
        'Can leak sensitive data such as configs, keys, or environment files.',
        'Typical mitigations: path normalization, allowlists, and sandboxed file access.'
      ],
      expanded: false
    },
    {
      title: 'CSRF',
      summary: 'A user browser is tricked into sending unintended authenticated requests.',
      details: [
        'High impact when sensitive actions are one-click and unprotected.',
        'Especially dangerous on state-changing endpoints.',
        'Typical mitigations: CSRF tokens, same-site cookies, and re-auth for critical actions.'
      ],
      expanded: false
    },
    {
      title: 'Sensitive Data Exposure',
      summary: 'Sensitive information is revealed in responses, pages, or client-side artifacts.',
      details: [
        'May expose tokens, credentials, API keys, or internal identifiers.',
        'Leaked secrets can be chained with other vulnerabilities for larger compromise.',
        'Typical mitigations: secret management, output filtering, and secure logging.'
      ],
      expanded: false
    },
    {
      title: 'Open Redirect',
      summary: 'Unvalidated redirects send users to attacker-controlled destinations.',
      details: [
        'Used in phishing flows to abuse trust in legitimate domains.',
        'Can chain with other bugs for stronger social-engineering attacks.',
        'Typical mitigations: destination allowlists and signed redirect targets.'
      ],
      expanded: false
    },
    {
      title: 'Broken Authentication',
      summary: 'Weak authentication/session controls allow account abuse or unauthorized access.',
      details: [
        'Includes weak session handling, missing hardening, and brute-force gaps.',
        'Can lead to account takeover or exposure of privileged functionality.',
        'Typical mitigations: strong auth controls, secure cookies, and abuse-rate protections.'
      ],
      expanded: false
    }
  ];

  sourceCodeReview: AboutCard = {
    title: 'Source Code Review',
    summary: 'Upload frontend files and receive a focused report on risky code patterns.',
    details: [
      'Checks JavaScript and HTML for patterns that can lead to security issues.',
      'Helps developers catch vulnerabilities earlier in the SDLC.',
      'Returns a readable report that supports remediation planning and follow-up testing.'
    ],
    expanded: false
  };

  backendTech: AboutCard = {
    title: 'Backend Technologies',
    summary: 'Core backend stack used to run scanning workflows and APIs.',
    details: [
      'ASP.NET Core Web API (.NET 8) for endpoints and orchestration.',
      'Entity Framework Core with SQL Server for persistence and reporting.',
      'JWT-based authentication and protected API routes.',
      'Python scanner integration executed through wrapper scripts from the backend service.'
    ],
    expanded: false
  };

  frontendTech: AboutCard = {
    title: 'Frontend Technologies',
    summary: 'Client-side stack used for dashboard, reports, and scan workflows.',
    details: [
      'Angular 19 with standalone components and TypeScript.',
      'RxJS for reactive service calls and state updates.',
      'Bootstrap-based responsive layout and UI structure.',
      'Chart.js visualizations for report insights and score presentation.'
    ],
    expanded: false
  };

  // دالة فتح وإغلاق الكارت بشكل مرن ومتوافق مع الـ Interface
  toggleCard(card: AboutCard): void {
    card.expanded = !card.expanded;
  }
}