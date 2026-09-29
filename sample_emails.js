const EMAILS = [
  {
    "id": "MSG-001",
    "from": "security@paypa1-support.com",
    "subj": "Urgent: verify your account",
    "risk": 92,
    "lvl": "CRITICAL",
    "cls": "Credential Phishing (suspected)",
    "conf": 85,
    "time": "08:13",
    "ind": [
      [
        "Look-alike sender domain",
        "HIGH",
        "paypa1-support.com imitates \"paypal\"",
        "Inferred",
        88
      ],
      [
        "Urgency language",
        "MEDIUM",
        "Matched: urgent, verify your",
        "Rule-based",
        70
      ],
      [
        "Link text shows a different site than the real link",
        "HIGH",
        "Shows a trusted site but goes to another domain",
        "Observed",
        93
      ]
    ],
    "ip": "203.0.113.1",
    "geo": "not looked up",
    "dom": "paypa1-support.com",
    "age": "not checked",
    "chain": [
      "Email URL",
      "(sample)"
    ],
    "att": "None",
    "attd": "none",
    "dna": "TT-SAMPLE-001",
    "to": "demo@example.com",
    "reply": "none",
    "rpath": "security@paypa1-support.com",
    "mid": "<sample1@example.com>",
    "date": "29 Sep 2026 08:13",
    "spf": "FAIL",
    "dkim": "FAIL",
    "dmarc": "FAIL",
    "arc": "none",
    "authres": "sample data"
  },
  {
    "id": "MSG-002",
    "from": "billing@micros0ft-billing.com",
    "subj": "Your Microsoft 365 subscription expires",
    "risk": 85,
    "lvl": "HIGH",
    "cls": "Credential Phishing (suspected)",
    "conf": 83,
    "time": "08:26",
    "ind": [
      [
        "Look-alike sender domain",
        "HIGH",
        "micros0ft-billing.com imitates \"microsoft\"",
        "Inferred",
        88
      ],
      [
        "Urgency language",
        "MEDIUM",
        "Matched: expires",
        "Rule-based",
        70
      ]
    ],
    "ip": "203.0.113.2",
    "geo": "not looked up",
    "dom": "micros0ft-billing.com",
    "age": "not checked",
    "chain": [
      "Email URL",
      "(sample)"
    ],
    "att": "None",
    "attd": "none",
    "dna": "TT-SAMPLE-002",
    "to": "demo@example.com",
    "reply": "none",
    "rpath": "billing@micros0ft-billing.com",
    "mid": "<sample2@example.com>",
    "date": "29 Sep 2026 08:26",
    "spf": "FAIL",
    "dkim": "FAIL",
    "dmarc": "PASS",
    "arc": "none",
    "authres": "sample data"
  },
  {
    "id": "MSG-003",
    "from": "alerts@hdfc-secure-login.in",
    "subj": "Action required: KYC update",
    "risk": 88,
    "lvl": "HIGH",
    "cls": "Credential Phishing (suspected)",
    "conf": 84,
    "time": "08:39",
    "ind": [
      [
        "Look-alike sender domain",
        "HIGH",
        "hdfc-secure-login.in imitates \"hdfc\"",
        "Inferred",
        88
      ],
      [
        "Urgency language",
        "MEDIUM",
        "Matched: action required",
        "Rule-based",
        70
      ],
      [
        "URL shortener used",
        "MEDIUM",
        "bit.ly hides the final destination",
        "Observed",
        80
      ]
    ],
    "ip": "203.0.113.3",
    "geo": "not looked up",
    "dom": "hdfc-secure-login.in",
    "age": "not checked",
    "chain": [
      "Email URL",
      "(sample)"
    ],
    "att": "None",
    "attd": "none",
    "dna": "TT-SAMPLE-003",
    "to": "demo@example.com",
    "reply": "none",
    "rpath": "alerts@hdfc-secure-login.in",
    "mid": "<sample3@example.com>",
    "date": "29 Sep 2026 08:39",
    "spf": "PASS",
    "dkim": "FAIL",
    "dmarc": "FAIL",
    "arc": "none",
    "authres": "sample data"
  },
  {
    "id": "MSG-004",
    "from": "noreply@amazon-delivery.top",
    "subj": "Package on hold: confirm address",
    "risk": 78,
    "lvl": "HIGH",
    "cls": "Credential Phishing (suspected)",
    "conf": 81,
    "time": "09:52",
    "ind": [
      [
        "Look-alike sender domain",
        "HIGH",
        "amazon-delivery.top imitates \"amazon\"",
        "Inferred",
        88
      ],
      [
        "Link points to a raw IP address",
        "HIGH",
        "185.220.101.4",
        "Observed",
        90
      ]
    ],
    "ip": "203.0.113.4",
    "geo": "not looked up",
    "dom": "amazon-delivery.top",
    "age": "not checked",
    "chain": [
      "Email URL",
      "(sample)"
    ],
    "att": "None",
    "attd": "none",
    "dna": "TT-SAMPLE-004",
    "to": "demo@example.com",
    "reply": "none",
    "rpath": "noreply@amazon-delivery.top",
    "mid": "<sample4@example.com>",
    "date": "29 Sep 2026 09:52",
    "spf": "FAIL",
    "dkim": "PASS",
    "dmarc": "FAIL",
    "arc": "none",
    "authres": "sample data"
  },
  {
    "id": "MSG-005",
    "from": "support@netfl1x-account.com",
    "subj": "Payment declined, update your card",
    "risk": 81,
    "lvl": "HIGH",
    "cls": "Credential Phishing (suspected)",
    "conf": 82,
    "time": "09:05",
    "ind": [
      [
        "Look-alike sender domain",
        "HIGH",
        "netfl1x-account.com imitates \"netflix\"",
        "Inferred",
        88
      ],
      [
        "Payment / financial language",
        "MEDIUM",
        "Matched: payment",
        "Rule-based",
        70
      ],
      [
        "URL shortener used",
        "MEDIUM",
        "bit.ly hides the final destination",
        "Observed",
        80
      ]
    ],
    "ip": "203.0.113.5",
    "geo": "not looked up",
    "dom": "netfl1x-account.com",
    "age": "not checked",
    "chain": [
      "Email URL",
      "(sample)"
    ],
    "att": "None",
    "attd": "none",
    "dna": "TT-SAMPLE-005",
    "to": "demo@example.com",
    "reply": "none",
    "rpath": "support@netfl1x-account.com",
    "mid": "<sample5@example.com>",
    "date": "29 Sep 2026 09:05",
    "spf": "FAIL",
    "dkim": "FAIL",
    "dmarc": "PASS",
    "arc": "none",
    "authres": "sample data"
  },
  {
    "id": "MSG-006",
    "from": "docs@docusign-review.net",
    "subj": "Please review and sign document",
    "risk": 74,
    "lvl": "HIGH",
    "cls": "Credential Phishing (suspected)",
    "conf": 79,
    "time": "09:18",
    "ind": [
      [
        "Look-alike sender domain",
        "HIGH",
        "docusign-review.net imitates \"docusign\"",
        "Inferred",
        88
      ],
      [
        "Attachment type often abused",
        "MEDIUM",
        "agreement.html",
        "Observed",
        75
      ]
    ],
    "ip": "203.0.113.6",
    "geo": "not looked up",
    "dom": "docusign-review.net",
    "age": "not checked",
    "chain": [
      "Email URL",
      "(sample)"
    ],
    "att": "agreement.html",
    "attd": "agreement.html, 48213 bytes, sha256 9f2a4c1d7e30",
    "dna": "TT-SAMPLE-006",
    "to": "demo@example.com",
    "reply": "none",
    "rpath": "docs@docusign-review.net",
    "mid": "<sample6@example.com>",
    "date": "29 Sep 2026 09:18",
    "spf": "PASS",
    "dkim": "FAIL",
    "dmarc": "FAIL",
    "arc": "none",
    "authres": "sample data"
  },
  {
    "id": "MSG-007",
    "from": "it-helpdesk@company-support.org",
    "subj": "Password expires in 24 hours",
    "risk": 68,
    "lvl": "MEDIUM",
    "cls": "Credential Phishing (suspected)",
    "conf": 77,
    "time": "09:31",
    "ind": [
      [
        "Urgency language",
        "MEDIUM",
        "Matched: within 24 hours, password expires",
        "Rule-based",
        70
      ],
      [
        "URL shortener used",
        "MEDIUM",
        "bit.ly hides the final destination",
        "Observed",
        80
      ]
    ],
    "ip": "203.0.113.7",
    "geo": "not looked up",
    "dom": "company-support.org",
    "age": "not checked",
    "chain": [
      "Email URL",
      "(sample)"
    ],
    "att": "None",
    "attd": "none",
    "dna": "TT-SAMPLE-007",
    "to": "demo@example.com",
    "reply": "none",
    "rpath": "it-helpdesk@company-support.org",
    "mid": "<sample7@example.com>",
    "date": "29 Sep 2026 09:31",
    "spf": "PASS",
    "dkim": "PASS",
    "dmarc": "FAIL",
    "arc": "none",
    "authres": "sample data"
  },
  {
    "id": "MSG-008",
    "from": "hr@company-payroll.net",
    "subj": "Updated payroll schedule",
    "risk": 70,
    "lvl": "HIGH",
    "cls": "Business Email Compromise (suspected)",
    "conf": 78,
    "time": "10:44",
    "ind": [
      [
        "Reply-To domain differs from sender domain",
        "MEDIUM",
        "Reply-To is a free Gmail address",
        "Observed",
        90
      ],
      [
        "Payment / financial language",
        "MEDIUM",
        "Matched: payroll",
        "Rule-based",
        70
      ]
    ],
    "ip": "203.0.113.8",
    "geo": "not looked up",
    "dom": "company-payroll.net",
    "age": "not checked",
    "chain": [
      "Email URL",
      "(sample)"
    ],
    "att": "None",
    "attd": "none",
    "dna": "TT-SAMPLE-008",
    "to": "demo@example.com",
    "reply": "hr.payroll88@gmail.com",
    "rpath": "hr@company-payroll.net",
    "mid": "<sample8@example.com>",
    "date": "29 Sep 2026 10:44",
    "spf": "PASS",
    "dkim": "PASS",
    "dmarc": "FAIL",
    "arc": "none",
    "authres": "sample data"
  },
  {
    "id": "MSG-009",
    "from": "ceo@company-corp.co",
    "subj": "Urgent wire transfer needed",
    "risk": 89,
    "lvl": "HIGH",
    "cls": "Business Email Compromise (suspected)",
    "conf": 84,
    "time": "10:57",
    "ind": [
      [
        "Display name impersonates another identity",
        "HIGH",
        "Display name \"CEO\" does not match the sender address",
        "Inferred",
        85
      ],
      [
        "Reply-To domain differs from sender domain",
        "MEDIUM",
        "Reply-To is a free Gmail address",
        "Observed",
        90
      ],
      [
        "Payment / financial language",
        "MEDIUM",
        "Matched: wire transfer",
        "Rule-based",
        70
      ],
      [
        "Urgency language",
        "MEDIUM",
        "Matched: urgent",
        "Rule-based",
        70
      ]
    ],
    "ip": "203.0.113.9",
    "geo": "not looked up",
    "dom": "company-corp.co",
    "age": "not checked",
    "chain": [
      "Email URL",
      "(sample)"
    ],
    "att": "None",
    "attd": "none",
    "dna": "TT-SAMPLE-009",
    "to": "demo@example.com",
    "reply": "john.ceo88@gmail.com",
    "rpath": "ceo@company-corp.co",
    "mid": "<sample9@example.com>",
    "date": "29 Sep 2026 10:57",
    "spf": "PASS",
    "dkim": "FAIL",
    "dmarc": "FAIL",
    "arc": "none",
    "authres": "sample data"
  },
  {
    "id": "MSG-010",
    "from": "accounts@vendor-invoices.biz",
    "subj": "Invoice #4471 overdue",
    "risk": 83,
    "lvl": "HIGH",
    "cls": "Suspicious",
    "conf": 82,
    "time": "10:10",
    "ind": [
      [
        "Payment / financial language",
        "MEDIUM",
        "Matched: invoice, payment",
        "Rule-based",
        70
      ],
      [
        "Risky attachment type",
        "HIGH",
        "invoice_4471.docm (sha256 9f2a4c1d7e30...)",
        "Observed",
        92
      ]
    ],
    "ip": "203.0.113.10",
    "geo": "not looked up",
    "dom": "vendor-invoices.biz",
    "age": "not checked",
    "chain": [
      "Email URL",
      "(sample)"
    ],
    "att": "invoice_4471.docm",
    "attd": "invoice_4471.docm, 48213 bytes, sha256 9f2a4c1d7e30",
    "dna": "TT-SAMPLE-010",
    "to": "demo@example.com",
    "reply": "none",
    "rpath": "accounts@vendor-invoices.biz",
    "mid": "<sample10@example.com>",
    "date": "29 Sep 2026 10:10",
    "spf": "FAIL",
    "dkim": "PASS",
    "dmarc": "PASS",
    "arc": "none",
    "authres": "sample data"
  },
  {
    "id": "MSG-011",
    "from": "parcel@dhl-express-track.info",
    "subj": "Your parcel could not be delivered",
    "risk": 76,
    "lvl": "HIGH",
    "cls": "Credential Phishing (suspected)",
    "conf": 80,
    "time": "10:23",
    "ind": [
      [
        "Look-alike sender domain",
        "HIGH",
        "dhl-express-track.info imitates \"dhl\"",
        "Inferred",
        88
      ],
      [
        "URL shortener used",
        "MEDIUM",
        "bit.ly hides the final destination",
        "Observed",
        80
      ]
    ],
    "ip": "203.0.113.11",
    "geo": "not looked up",
    "dom": "dhl-express-track.info",
    "age": "not checked",
    "chain": [
      "Email URL",
      "(sample)"
    ],
    "att": "None",
    "attd": "none",
    "dna": "TT-SAMPLE-011",
    "to": "demo@example.com",
    "reply": "none",
    "rpath": "parcel@dhl-express-track.info",
    "mid": "<sample11@example.com>",
    "date": "29 Sep 2026 10:23",
    "spf": "PASS",
    "dkim": "FAIL",
    "dmarc": "PASS",
    "arc": "none",
    "authres": "sample data"
  },
  {
    "id": "MSG-012",
    "from": "security@faceb00k-alerts.com",
    "subj": "Someone tried to log in",
    "risk": 80,
    "lvl": "HIGH",
    "cls": "Credential Phishing (suspected)",
    "conf": 81,
    "time": "11:36",
    "ind": [
      [
        "Look-alike sender domain",
        "HIGH",
        "faceb00k-alerts.com imitates \"facebook\"",
        "Inferred",
        88
      ],
      [
        "Urgency language",
        "MEDIUM",
        "Matched: verify your",
        "Rule-based",
        70
      ],
      [
        "Link text shows a different site than the real link",
        "HIGH",
        "Shows a trusted site but goes to another domain",
        "Observed",
        93
      ]
    ],
    "ip": "203.0.113.12",
    "geo": "not looked up",
    "dom": "faceb00k-alerts.com",
    "age": "not checked",
    "chain": [
      "Email URL",
      "(sample)"
    ],
    "att": "None",
    "attd": "none",
    "dna": "TT-SAMPLE-012",
    "to": "demo@example.com",
    "reply": "none",
    "rpath": "security@faceb00k-alerts.com",
    "mid": "<sample12@example.com>",
    "date": "29 Sep 2026 11:36",
    "spf": "FAIL",
    "dkim": "FAIL",
    "dmarc": "FAIL",
    "arc": "none",
    "authres": "sample data"
  },
  {
    "id": "MSG-013",
    "from": "digest@github.com",
    "subj": "Your weekly digest",
    "risk": 0,
    "lvl": "LOW",
    "cls": "No indicators (likely legitimate)",
    "conf": 55,
    "time": "11:49",
    "ind": [
      [
        "No rule-based indicators fired",
        "LOW",
        "Checked auth results, links, attachments",
        "Observed",
        80
      ]
    ],
    "ip": "203.0.113.13",
    "geo": "not looked up",
    "dom": "github.com",
    "age": "not checked",
    "chain": [
      "Email URL",
      "(sample)"
    ],
    "att": "None",
    "attd": "none",
    "dna": "TT-SAMPLE-013",
    "to": "demo@example.com",
    "reply": "none",
    "rpath": "digest@github.com",
    "mid": "<sample13@example.com>",
    "date": "29 Sep 2026 11:49",
    "spf": "PASS",
    "dkim": "PASS",
    "dmarc": "PASS",
    "arc": "none",
    "authres": "sample data"
  },
  {
    "id": "MSG-014",
    "from": "no-reply@accounts.google.com",
    "subj": "Security alert",
    "risk": 12,
    "lvl": "LOW",
    "cls": "No indicators (likely legitimate)",
    "conf": 59,
    "time": "11:02",
    "ind": [
      [
        "Urgency language",
        "MEDIUM",
        "Matched: action required",
        "Rule-based",
        70
      ]
    ],
    "ip": "203.0.113.14",
    "geo": "not looked up",
    "dom": "accounts.google.com",
    "age": "not checked",
    "chain": [
      "Email URL",
      "(sample)"
    ],
    "att": "None",
    "attd": "none",
    "dna": "TT-SAMPLE-014",
    "to": "demo@example.com",
    "reply": "none",
    "rpath": "no-reply@accounts.google.com",
    "mid": "<sample14@example.com>",
    "date": "29 Sep 2026 11:02",
    "spf": "PASS",
    "dkim": "PASS",
    "dmarc": "PASS",
    "arc": "none",
    "authres": "sample data"
  },
  {
    "id": "MSG-015",
    "from": "newsletter@linkedin.com",
    "subj": "5 jobs that match your profile",
    "risk": 0,
    "lvl": "LOW",
    "cls": "No indicators (likely legitimate)",
    "conf": 55,
    "time": "11:15",
    "ind": [
      [
        "No rule-based indicators fired",
        "LOW",
        "Checked auth results, links, attachments",
        "Observed",
        80
      ]
    ],
    "ip": "203.0.113.15",
    "geo": "not looked up",
    "dom": "linkedin.com",
    "age": "not checked",
    "chain": [
      "Email URL",
      "(sample)"
    ],
    "att": "None",
    "attd": "none",
    "dna": "TT-SAMPLE-015",
    "to": "demo@example.com",
    "reply": "none",
    "rpath": "newsletter@linkedin.com",
    "mid": "<sample15@example.com>",
    "date": "29 Sep 2026 11:15",
    "spf": "PASS",
    "dkim": "PASS",
    "dmarc": "PASS",
    "arc": "none",
    "authres": "sample data"
  },
  {
    "id": "MSG-016",
    "from": "receipts@swiggy.in",
    "subj": "Your order receipt",
    "risk": 12,
    "lvl": "LOW",
    "cls": "No indicators (likely legitimate)",
    "conf": 59,
    "time": "12:28",
    "ind": [
      [
        "Payment / financial language",
        "MEDIUM",
        "Matched: invoice, payment",
        "Rule-based",
        70
      ]
    ],
    "ip": "203.0.113.16",
    "geo": "not looked up",
    "dom": "swiggy.in",
    "age": "not checked",
    "chain": [
      "Email URL",
      "(sample)"
    ],
    "att": "None",
    "attd": "none",
    "dna": "TT-SAMPLE-016",
    "to": "demo@example.com",
    "reply": "none",
    "rpath": "receipts@swiggy.in",
    "mid": "<sample16@example.com>",
    "date": "29 Sep 2026 12:28",
    "spf": "PASS",
    "dkim": "PASS",
    "dmarc": "PASS",
    "arc": "none",
    "authres": "sample data"
  },
  {
    "id": "MSG-017",
    "from": "team@devpost.com",
    "subj": "Hackathon submissions close soon",
    "risk": 12,
    "lvl": "LOW",
    "cls": "No indicators (likely legitimate)",
    "conf": 59,
    "time": "12:41",
    "ind": [
      [
        "Urgency language",
        "MEDIUM",
        "Matched: expires",
        "Rule-based",
        70
      ]
    ],
    "ip": "203.0.113.17",
    "geo": "not looked up",
    "dom": "devpost.com",
    "age": "not checked",
    "chain": [
      "Email URL",
      "(sample)"
    ],
    "att": "None",
    "attd": "none",
    "dna": "TT-SAMPLE-017",
    "to": "demo@example.com",
    "reply": "none",
    "rpath": "team@devpost.com",
    "mid": "<sample17@example.com>",
    "date": "29 Sep 2026 12:41",
    "spf": "PASS",
    "dkim": "PASS",
    "dmarc": "PASS",
    "arc": "none",
    "authres": "sample data"
  },
  {
    "id": "MSG-018",
    "from": "noreply@irctc.co.in",
    "subj": "Ticket booking confirmation",
    "risk": 0,
    "lvl": "LOW",
    "cls": "No indicators (likely legitimate)",
    "conf": 55,
    "time": "12:54",
    "ind": [
      [
        "No rule-based indicators fired",
        "LOW",
        "Checked auth results, links, attachments",
        "Observed",
        80
      ]
    ],
    "ip": "203.0.113.18",
    "geo": "not looked up",
    "dom": "irctc.co.in",
    "age": "not checked",
    "chain": [
      "Email URL",
      "(sample)"
    ],
    "att": "None",
    "attd": "none",
    "dna": "TT-SAMPLE-018",
    "to": "demo@example.com",
    "reply": "none",
    "rpath": "noreply@irctc.co.in",
    "mid": "<sample18@example.com>",
    "date": "29 Sep 2026 12:54",
    "spf": "PASS",
    "dkim": "PASS",
    "dmarc": "PASS",
    "arc": "none",
    "authres": "sample data"
  },
  {
    "id": "MSG-019",
    "from": "info@coursera.org",
    "subj": "Your course is waiting for you",
    "risk": 0,
    "lvl": "LOW",
    "cls": "No indicators (likely legitimate)",
    "conf": 55,
    "time": "12:07",
    "ind": [
      [
        "No rule-based indicators fired",
        "LOW",
        "Checked auth results, links, attachments",
        "Observed",
        80
      ]
    ],
    "ip": "203.0.113.19",
    "geo": "not looked up",
    "dom": "coursera.org",
    "age": "not checked",
    "chain": [
      "Email URL",
      "(sample)"
    ],
    "att": "None",
    "attd": "none",
    "dna": "TT-SAMPLE-019",
    "to": "demo@example.com",
    "reply": "none",
    "rpath": "info@coursera.org",
    "mid": "<sample19@example.com>",
    "date": "29 Sep 2026 12:07",
    "spf": "PASS",
    "dkim": "PASS",
    "dmarc": "PASS",
    "arc": "none",
    "authres": "sample data"
  },
  {
    "id": "MSG-020",
    "from": "noreply@zoom.us",
    "subj": "Meeting reminder: Project sync",
    "risk": 0,
    "lvl": "LOW",
    "cls": "No indicators (likely legitimate)",
    "conf": 55,
    "time": "13:20",
    "ind": [
      [
        "No rule-based indicators fired",
        "LOW",
        "Checked auth results, links, attachments",
        "Observed",
        80
      ]
    ],
    "ip": "203.0.113.20",
    "geo": "not looked up",
    "dom": "zoom.us",
    "age": "not checked",
    "chain": [
      "Email URL",
      "(sample)"
    ],
    "att": "None",
    "attd": "none",
    "dna": "TT-SAMPLE-020",
    "to": "demo@example.com",
    "reply": "none",
    "rpath": "noreply@zoom.us",
    "mid": "<sample20@example.com>",
    "date": "29 Sep 2026 13:20",
    "spf": "PASS",
    "dkim": "PASS",
    "dmarc": "PASS",
    "arc": "none",
    "authres": "sample data"
  }
];