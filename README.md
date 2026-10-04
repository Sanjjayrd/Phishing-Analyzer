# Phishing Email Analyser

A free, privacy-first educational tool for spotting phishing and social-engineering warning signs in suspicious emails.

**Live demo:** open index.html directly in your browser — no installation needed.

---

## What it does

Paste the full text of a suspicious email (and its headers, if you have them) and click **Analyse Email**. You get:

- A **phishing risk score** from 0 to 100
- A **classification**: Low Risk, Suspicious, or High Risk
- A **plain-English explanation** of every warning sign that triggered, including the exact text that matched
- **Practical recommendations** for what to do next
- A **Headers tab** showing SPF, DKIM and DMARC authentication results (when headers are pasted)

---

## Privacy — your email never leaves your device

All analysis happens inside your browser using JavaScript that is part of this page.
There is no server, no database, no AI API, no analytics and no tracking of any kind.

The Content-Security-Policy header in index.html enforces this at the browser level:
connect-src 'none' blocks every network request this page could ever make.

**To verify it yourself:** open your browser's developer tools (F12), go to the Network tab, clear it, paste an email and click Analyse. Nothing appears in the Network tab.

---

## How to use it

### Option 1 — open it directly (no installation)

Double-click index.html. It opens in your default browser and works immediately.

### Option 2 — host it for free on GitHub Pages

1. Create a free account at [github.com](https://github.com)
2. Create a new repository (click the **+** button → New repository)
3. Upload all four files: index.html, styles.css, avicon.svg and the js/ folder
4. Go to **Settings → Pages** and set the source to the main branch
5. GitHub gives you a public URL such as https://yourusername.github.io/phishing-analyser/

That URL is free, always-on, and requires no maintenance.

---

## Project structure

`
index.html          The page — layout, tabs and all static content
styles.css          All styling — dark theme, responsive, no external fonts
favicon.svg         Browser tab icon (self-contained SVG, no CDN)
js/
  rules.js          THE RULE BOOK — every check, its points, and its explanation
  analyzer.js       THE ENGINE — parses email text, scores, and explains findings
  demos.js          Six fictional demo emails for learning
  app.js            THE INTERFACE — wires the engine to the UI
tests/
  analyze.test.js   43 automated tests for the engine and rule book
  ui.test.js        UI smoke tests
`

---

## How the scoring works

1. Every triggered check adds its **points** to its **category**.
2. Each category has a **cap** — so repeating one trick cannot inflate the score.
3. The category totals are added together.
4. The final score is **capped at 100**.

The scoring table is visible in the **How scoring works** tab of the results — nothing is hidden.

| Score | Classification | Meaning |
|-------|---------------|---------|
| 0–24  | Low Risk       | Little or no evidence of classic phishing patterns |
| 25–54 | Suspicious     | Several warning signs present — treat with caution |
| 55–100 | High Risk     | Strongly matches known phishing patterns |

---

## What the tool checks for

| Category | Examples of what is detected |
|----------|------------------------------|
| Urgency and pressure | "Act now", "within 24 hours", "final notice" |
| Threats | Account suspension, legal action threats |
| Credential requests | Password requests, MFA/OTP code requests, "verify your account" |
| Payment requests | Gift card requests, crypto/wire transfers, card detail requests |
| Invoices / BEC | Fake invoices, bank-detail changes, secrecy requests |
| Suspicious links | Raw IP addresses, shortened URLs, look-alike domains, brand-in-subdomain trick, punycode, redirect-in-URL |
| Risky attachments | Executable files, macro-enabled Office docs, double extensions, password-protected archives |
| Impersonation | Generic greetings, IT/security team language, display name vs. real address mismatch |
| Email authentication | SPF fail, DKIM fail/missing, DMARC fail, Reply-To mismatch |
| Obfuscation | Invisible characters, spaced-out words, encoded blobs |

---

## How to add a new check

All checks live in **js/rules.js**. Open it and find the PHRASE_RULES array.
Copy an existing entry and change these fields:

`js
{
  id: 'my-new-check',          // short unique name, no spaces
  category: 'urgency',         // which category's cap applies
  title: 'What the user sees', // shown as the heading in results
  weight: 8,                   // how many points it adds (0-20 typical)
  why: 'Plain-English explanation of why this is suspicious.',
  tip: 'Optional advice for the user.',
  patterns: [
    /\bthe phrase to look for\b/,
    /\bor another phrase\b/
  ]
}
`

Save the file and reload the page — the new check appears automatically in the results and in the "How scoring works" tab.

---

## Safety disclaimer

This is an **educational triage tool**. It identifies warning signs by matching text against known patterns.

- It **cannot prove** an email is malicious.
- It **cannot prove** an email is safe. A low score only means nothing on the checklist matched.
- It cannot see images, QR codes, real attachment contents or anything hidden behind a link.

**Never click a link or open an attachment in a suspected phishing email just to test it.**
Always verify unexpected messages through the organisation's official website, app or a phone number you already hold.

---

## Running the tests

You need [Node.js](https://nodejs.org) installed (free). Then:

`
node tests/analyze.test.js
`

43 tests covering the engine, every rule category, scoring caps, edge cases and safety properties.

---

## Technical notes

- **No build step.** Open index.html directly — no 
pm install, no bundler, no compilation.
- **No dependencies.** Zero packages. The whole application is four JavaScript files.
- **No external requests.** No CDN fonts, no analytics, no tracking pixels, no API calls.
- **Works offline.** Once loaded, the page works with no internet connection at all.
- **Printable.** The results panel prints cleanly (all tabs visible, input area hidden).
- **Accessible.** ARIA roles, keyboard navigation, skip link, high-contrast and reduced-motion support.
