/* ==========================================================================
   Phishing Email Analyser - js/rules.js
   --------------------------------------------------------------------------
   THE RULE BOOK.

   Every warning sign this application knows about is defined in this file.
   Nothing in here talks to the internet, and nothing in here decides the
   final score - js/analyzer.js adds up the points defined here.

   Contents:
     1. CATEGORIES  - groups of rules, each with a maximum number of points
     2. DATA        - reference lists (brands, shorteners, file extensions...)
     3. PHRASE_RULES- checks that look for text patterns
     4. CUSTOM_RULES- checks that need real logic (URLs, attachments, headers)
     5. Helpers and exports

   HOW TO ADD A NEW CHECK (plain-English guide in README.md):
     Copy an existing entry in PHRASE_RULES and change its id, title, weight,
     why and patterns. That is all you need to do - the new check will appear
     automatically in the results and in the "Scoring" tab.
   ========================================================================== */
(function (root, factory) {
  'use strict';
  /* This wrapper lets the same file work in two places:
       - inside the web page     -> attaches itself to window.PEA.rules
       - inside the developer test script, which runs on Node.js
     It downloads nothing and depends on nothing. */
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.PEA = root.PEA || {};
    root.PEA.rules = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /* ========================================================================
     1. CATEGORIES
     -----------------------------------------------------------------------
     Every indicator belongs to a category. A category has a CAP: the most
     points that category may contribute in total.

     Why caps exist: if a scam email says "urgent" nine times, that is still
     one trick. Without a cap, repetition would inflate the score and make
     the result misleading and impossible to audit.
     ======================================================================== */
  var CATEGORIES = {
    urgency: {
      label: 'Urgency and pressure',
      cap: 10,
      blurb: 'Language designed to rush you past your own common sense.'
    },
    threats: {
      label: 'Threats and consequences',
      cap: 12,
      blurb: 'Frightening you with loss of access, money or legal trouble.'
    },
    credentials: {
      label: 'Credential and code requests',
      cap: 24,
      blurb: 'Attempts to obtain your password or a one-time sign-in code.'
    },
    payment: {
      label: 'Payment and money requests',
      cap: 20,
      blurb: 'Attempts to move money, gift cards or card details.'
    },
    bec: {
      label: 'Invoices and bank-detail changes',
      cap: 18,
      blurb: 'Business email compromise: fake invoices and "new" bank details.'
    },
    links: {
      label: 'Suspicious links',
      cap: 24,
      blurb: 'Links that hide where they really lead.'
    },
    attachments: {
      label: 'Risky attachments',
      cap: 26,
      blurb: 'File types that can install software or run code.'
    },
    impersonation: {
      label: 'Impersonation',
      cap: 18,
      blurb: 'Pretending to be a brand, an IT department or a senior colleague.'
    },
    headers: {
      label: 'Email authentication and routing',
      cap: 26,
      blurb: 'Technical evidence from pasted headers (SPF, DKIM, DMARC).'
    },
    obfuscation: {
      label: 'Obfuscation and evasive tricks',
      cap: 10,
      blurb: 'Invisible characters and other tricks used to defeat filters.'
    }
  };

  /* ========================================================================
     2. DATA - the reference lists used by the checks
     ======================================================================== */

  /* Brands that phishing emails most often pretend to be, together with the
     domains those brands genuinely use. Used to spot, for example, a
     "Microsoft" display name sent from a domain Microsoft does not own. */
  var BRANDS = [
    { name: 'Microsoft', tokens: ['microsoft', 'microsoft 365', 'office 365', 'ms365', 'o365'],
      domains: ['microsoft.com', 'microsoftonline.com', 'microsoft365.com', 'office.com', 'office365.com', 'live.com', 'outlook.com', 'sharepoint.com'] },
    { name: 'Apple', tokens: ['apple', 'icloud', 'itunes'],
      domains: ['apple.com', 'icloud.com', 'itunes.com'] },
    { name: 'Google', tokens: ['google', 'gmail'],
      domains: ['google.com', 'gmail.com', 'googlemail.com'] },
    { name: 'Amazon', tokens: ['amazon', 'aws'],
      domains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.ca', 'amazon.in', 'aws.amazon.com'] },
    { name: 'PayPal', tokens: ['paypal'],
      domains: ['paypal.com', 'paypal.co.uk', 'paypal.com.au'] },
    { name: 'Netflix', tokens: ['netflix'], domains: ['netflix.com'] },
    { name: 'Meta', tokens: ['facebook', 'meta', 'instagram', 'whatsapp'],
      domains: ['facebook.com', 'meta.com', 'instagram.com', 'whatsapp.com'] },
    { name: 'LinkedIn', tokens: ['linkedin'], domains: ['linkedin.com'] },
    { name: 'Dropbox', tokens: ['dropbox'], domains: ['dropbox.com'] },
    { name: 'Adobe', tokens: ['adobe'], domains: ['adobe.com'] },
    { name: 'Spotify', tokens: ['spotify'], domains: ['spotify.com'] },
    { name: 'Zoom', tokens: ['zoom'], domains: ['zoom.us', 'zoom.com'] },
    { name: 'DocuSign', tokens: ['docusign'], domains: ['docusign.com', 'docusign.net'] },
    { name: 'DHL', tokens: ['dhl'], domains: ['dhl.com', 'dhl.de', 'dhl.co.uk'] },
    { name: 'UPS', tokens: ['ups', 'united parcel service'], domains: ['ups.com'] },
    { name: 'FedEx', tokens: ['fedex'], domains: ['fedex.com'] },
    { name: 'Royal Mail', tokens: ['royal mail', 'royalmail'],
      domains: ['royalmail.com', 'royalmailgroup.com'] },
    { name: 'USPS', tokens: ['usps', 'united states postal'], domains: ['usps.com'] },
    { name: 'HSBC', tokens: ['hsbc'], domains: ['hsbc.com', 'hsbc.co.uk'] },
    { name: 'Barclays', tokens: ['barclays'], domains: ['barclays.co.uk', 'barclays.com'] },
    { name: 'Lloyds Bank', tokens: ['lloyds'], domains: ['lloydsbank.com', 'lloydsbank.co.uk'] },
    { name: 'NatWest', tokens: ['natwest'], domains: ['natwest.com', 'natwest.co.uk'] },
    { name: 'Chase', tokens: ['chase bank', 'jpmorgan chase'], domains: ['chase.com', 'jpmorgan.com'] },
    { name: 'Bank of America', tokens: ['bank of america', 'bofa'], domains: ['bankofamerica.com'] },
    { name: 'Wells Fargo', tokens: ['wells fargo'], domains: ['wellsfargo.com'] },
    { name: 'Santander', tokens: ['santander'], domains: ['santander.com', 'santander.co.uk'] },
    { name: 'HMRC', tokens: ['hmrc', 'hm revenue'], domains: ['gov.uk', 'hmrc.gov.uk'] },
    { name: 'IRS', tokens: ['irs', 'internal revenue service'], domains: ['irs.gov'] },
    { name: 'eBay', tokens: ['ebay'], domains: ['ebay.com', 'ebay.co.uk'] },
    { name: 'Stripe', tokens: ['stripe'], domains: ['stripe.com'] },
    { name: 'QuickBooks', tokens: ['quickbooks', 'intuit'], domains: ['intuit.com', 'quickbooks.com'] },
    { name: 'Salesforce', tokens: ['salesforce'], domains: ['salesforce.com'] }
  ];

  /* Well-known link-shortening services. A short link is not bad by itself,
     but it hides the real destination - which is exactly what attackers want. */
  var SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'tiny.cc', 't.co', 'goo.gl', 'is.gd', 'buff.ly',
    'ow.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy', 's.id', 't.ly',
    'urlz.fr', 'bit.do', 'adf.ly', 'shorte.st', 'bl.ink', 'snip.ly', 'v.gd',
    'clck.ru', 'qrco.de', 'surl.li', 'chilp.it', 'gg.gg', 'kutt.it',
    'trib.al', 'x.co', 'u.to', '9qr.de'
  ];

  /* Reserved documentation domains that behave like a shortener, used only by
     the demonstration emails. We deliberately do not point the demos at a real
     shortener service: short codes get recycled, so a harmless-looking example
     link could one day lead somewhere harmful. "example" is a reserved domain
     ending that can never be registered by anybody. */
  var DOCUMENTATION_SHORTENERS = ['link.example', 'go.example', 'url.example'];

  /* File extensions that can run code or install software on your computer. */
  var EXECUTABLE_EXTS = ['exe', 'com', 'scr', 'pif', 'bat', 'cmd', 'js', 'jse',
    'vbs', 'vbe', 'wsf', 'wsh', 'ps1', 'psm1', 'msi', 'msp', 'lnk', 'url',
    'hta', 'jar', 'reg', 'cpl', 'dll', 'gadget', 'application', 'xll',
    'iso', 'img', 'vhd', 'vhdx'];

  /* Office documents allowed to contain macros. */
  var MACRO_EXTS = ['docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'potm', 'xlam',
    'sldm', 'xla', 'xlsb'];

  /* Older Office formats that can also carry macros. These only raise a flag
     when macro language is actually present in the message. */
  var LEGACY_OFFICE_EXTS = ['doc', 'xls', 'ppt'];

  /* Archive formats, used to hide payloads from virus scanners. */
  var ARCHIVE_EXTS = ['zip', 'rar', '7z', 'gz', 'tgz', 'bz2', 'cab', 'ace',
    'arj', 'lzh', 'tar'];

  /* Web pages used as attachments: a local file can fake a sign-in page and
     capture what you type without needing the internet at all. */
  var HTML_EXTS = ['html', 'htm', 'shtml', 'xhtml', 'mht', 'mhtml'];

  /* Harmless-looking first halves of a double extension, e.g. Invoice.pdf.exe */
  var DECOY_EXTS = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt',
    'jpg', 'jpeg', 'png', 'gif', 'bmp', 'rtf', 'csv', 'xml', 'htm', 'html',
    'mp3', 'mp4', 'wav', 'zip'];

  /* Domain endings frequently used for throwaway malicious domains. */
  var RISKY_TLDS = ['zip', 'mov', 'top', 'click', 'link', 'country', 'gq',
    'tk', 'ml', 'cf', 'ga', 'buzz', 'rest', 'loan', 'quest', 'monster',
    'sbs', 'cfd', 'icu', 'cyou', 'cam', 'bar', 'fit', 'mom', 'lol', 'autos',
    'boats', 'kim', 'wang', 'men', 'win', 'bid', 'trade', 'review',
    'download', 'racing', 'party', 'gdn', 'stream', 'surf', 'casa', 'wiki'];

  /* Country-style domain endings made of two parts. Needed so that
     "example.co.uk" is read as the domain "example.co.uk" and not "co.uk". */
  var TWO_PART_SUFFIXES = ['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk',
    'co.nz', 'net.nz', 'org.nz', 'com.au', 'net.au', 'org.au', 'edu.au',
    'gov.au', 'co.jp', 'ne.jp', 'or.jp', 'com.br', 'com.cn', 'com.hk',
    'com.sg', 'com.my', 'com.tw', 'co.in', 'co.za', 'co.kr', 'co.il',
    'com.mx', 'com.tr', 'com.ar', 'com.pl', 'com.ua', 'co.id', 'com.ph',
    'com.vn', 'co.th', 'com.sa', 'com.pk', 'com.ng', 'co.ke', 'gov.in',
    'ac.in', 'edu.in', 'com.eg', 'com.es', 'com.it', 'co.at', 'or.at'];

  /* Path words used by fake sign-in pages. */
  var CREDENTIAL_PATH_WORDS = ['login', 'log-in', 'signin', 'sign-in', 'verify',
    'verification', 'secure', 'security', 'account', 'accounts', 'update',
    'confirm', 'webscr', 'recover', 'password', 'auth', 'authenticate',
    'unlock', 'billing', 'payment', 'reset'];

  /* Words attackers spell out letter-by-letter to beat text filters. */
  var SPACED_WORDS = ['click', 'verify', 'login', 'urgent', 'password', 'bank',
    'invoice', 'account', 'secure', 'update', 'confirm', 'payment',
    'suspended', 'signin', 'paypal', 'microsoft'];

  /* ========================================================================
     3. PHRASE_RULES - the text-based warning signs
     -----------------------------------------------------------------------
     Each rule looks like this:
       id       - short unique name (also used by the developer test script)
       category - which category's point cap applies to it
       title    - heading shown to the user
       weight   - how many points it adds (before category caps)
       why      - plain-English explanation of the trick
       tip      - optional extra advice
       patterns - regular expressions that trigger the rule
       unless   - optional regular expressions that CANCEL the rule, used so we
                  never accuse a legitimate security warning that says
                  "we will never ask for your password"
     ======================================================================== */
  var PHRASE_RULES = [

    /* ---------- Urgency and pressure ---------- */
    {
      id: 'urgency-pressure',
      category: 'urgency',
      title: 'Urgency and pressure language',
      weight: 8,
      why: 'Phishing emails create artificial time pressure so that you act before you think. Legitimate organisations rarely demand action within hours.',
      tip: 'Real account problems do not get worse because you took ten minutes to verify the message. Attackers rely on you not checking.',
      patterns: [
        /\burgent(ly)?\b/,
        /\bimmediate(ly)?\b/,
        /\basap\b/,
        /\bas soon as possible\b/,
        /\bact (now|today|immediately)\b/,
        /\bhurry\b/,
        /\bdon'?t delay\b/,
        /\btime[- ]sensitive\b/,
        /\bfinal (notice|warning|reminder|chance)\b/,
        /\blast (chance|warning|reminder)\b/,
        /\bwithin (the )?(next )?(\d+|twenty|twenty-?four|forty-?eight|seventy-?two|ninety)\s?(hours?|hrs?|minutes?|days?)\b/,
        /\bexpires? (today|tonight|soon|in \d+)\b/,
        /\bwill expire\b/,
        /\bprompt action\b/,
        /\brequires? immediate\b/,
        /\brespond (immediately|now|today)\b/,
        /\bno time to lose\b/,
        /\bavoid (service )?(interruption|disruption|losing)\b/
      ]
    },

    /* ---------- Threats and consequences ---------- */
    {
      id: 'account-suspension-threat',
      category: 'threats',
      title: 'Threat of account suspension, closure or loss of access',
      weight: 10,
      why: 'Fear is the strongest lever in social engineering. Attackers threaten to close or lock your account so that "fixing it" feels more urgent than checking whether the message is genuine.',
      tip: 'A genuine provider will not ask you to restore access through a link in an unexpected email.',
      patterns: [
        /\baccount (will be|has been|may be|is) (suspend|clos|lock|terminat|deactivat|delet|restrict|limit|disabl)\w*/,
        /\b(suspend|clos|terminat|deactivat|delet|restrict)\w* (your|the) account/,
        /\bpermanently (closed|deleted|suspended|locked)\b/,
        /\blose (permanent )?access\b/,
        /\baccess (will be|has been|may be) (restricted|revoked|blocked|limited|denied|suspended)\b/,
        /\bunable to (access|log ?in|sign ?in|send|receive)\b/,
        /\baccount (has|have) been (flagged|locked|limited|compromised|blocked|restricted|disabled)\b/,
        /\b(temporary|temporarily) (suspended|locked|disabled|restricted)\b/,
        /\bwithout (further )?(notice|warning)\b/,
        /\blegal action\b/,
        /\bfurther action will be taken\b/,
        /\b(mailbox|mailbox storage|account) (is|has been) (over (quota|limit|storage)|full)\b/
      ]
    },

    /* ---------- Credential and code requests ---------- */
    {
      id: 'password-request',
      category: 'credentials',
      title: 'Request for a password or passphrase',
      weight: 18,
      why: 'No legitimate organisation asks for your password by email, and no IT department needs you to "confirm" it. A password request is one of the single strongest phishing indicators there is.',
      tip: 'Never send a password by email, and never type it into a page you reached from a link in a message.',
      patterns: [
        /\b(enter|provide|confirm|verify|validate|send|reply with|supply|update|re-?enter|type|submit|give|share) (us )?(your )?(current |old |existing |new )?(password|passphrase|pass ?word)\b/,
        /\bpassword (is )?(required|needed|expired|has expired|will expire|must be (changed|reset|updated|confirmed))\b/,
        /\byour password (has|will) expir\w*/,
        /\bconfirm your password\b/,
        /\bupdate your password\b/,
        /\bshare your password\b/,
        /\busername and password\b/,
        /\bcredentials? (are )?(required|needed|below|attached)\b/,
        /\bpaste your password\b/
      ],
      /* A genuine security-awareness message says the opposite - do not flag it. */
      unless: [
        /\b(never|do not|don'?t|won'?t|will not|nobody) (ever )?(share|send|give|disclose|provide|ask|request|email|tell)\b[^.]{0,40}\bpassword/,
        /\bpassword should never be\b/,
        /\bwe will never (ask|request)\b/
      ]
    },
    {
      id: 'mfa-code-request',
      category: 'credentials',
      title: 'Request for a one-time / MFA verification code',
      weight: 18,
      why: 'One-time codes are the last barrier between an attacker and your account. If they can talk you into reading the code out, a stolen password becomes a full login. This is sometimes called "code phishing" or "MFA fatigue".',
      tip: 'Treat a code you receive like the key to your front door - never read it to anybody.',
      patterns: [
        /\b(one[- ]time|otp|verification|security|authentication|authorisation|authorization|access|sms|text|2fa|mfa|two[- ]factor|six[- ]digit|6[- ]digit|eight[- ]digit) code\b/,
        /\bcode (you|we|that) (just )?(sent|generated|received)\b/,
        /\b(enter|provide|send|share|forward|reply with|tell us|confirm|read out) [^.]{0,25}\b(code|otp|pin)\b/,
        /\bshare (the|your|this) (code|pin|otp)\b/,
        /\bpurchase code\b/,
        /\bauthenticator (code|number|app code)\b/
      ],
      unless: [
        /\b(never|do not|don'?t|won'?t|will not) (ever )?(share|send|give|disclose|forward|provide)\b[^.]{0,40}\b(code|pin|otp)\b/,
        /\bwe will never (ask|request)\b/
      ]
    },
    {
      id: 'credential-harvest-language',
      category: 'credentials',
      title: 'Credential-harvesting language ("verify your account")',
      weight: 12,
      why: 'This wording exists to move you onto a fake sign-in page where your username and password are captured. Genuine services normally tell you to open their app or to type their address yourself.',
      tip: 'If a message wants a login, navigate to the service yourself - do not use the link it gave you.',
      patterns: [
        /\bverify your (account|identity|details|information|email|mailbox|profile|records)\b/,
        /\bconfirm your (account|identity|details|information|email|mailbox|profile|records)\b/,
        /\bvalidate your (account|email|details|identity)\b/,
        /\bsign ?in to (verify|confirm|restore|keep|continue|unlock|secure|update)\b/,
        /\blog ?in to (verify|confirm|restore|keep|continue|unlock|secure|update)\b/,
        /\bclick here to (sign ?in|log ?in|verify|confirm|update|restore|unlock|secure)\b/,
        /\b(reactivate|re-activate|restore|unlock|recover) your (account|access|mailbox|profile)\b/,
        /\bupdate your (billing|account|payment|profile|security) (information|details|settings)\b/,
        /\bsecure your account\b/,
        /\bwe (need|require) to verify\b/,
        /\bto complete (this|the) (verification|process|update|request)\b/,
        /\bprotect your account by\b/
      ]
    },

    /* ---------- Payment and money requests ---------- */
    {
      id: 'gift-card-request',
      category: 'payment',
      title: 'Gift-card or voucher payment request',
      weight: 15,
      why: 'Gift cards are untraceable and irreversible. No legitimate business, tax office, police force or IT department is ever paid in gift cards - this request appears in a very large share of scams.',
      tip: 'Gift cards are a scam method, full stop. There is no legitimate exception.',
      patterns: [
        /\bgift ?cards?\b/,
        /\bitunes (card|voucher)\b/,
        /\bgoogle play (card|gift|voucher)\b/,
        /\bsteam (card|wallet|voucher)\b/,
        /\bamazon (gift )?(card|voucher)\b/,
        /\bapple (gift )?cards?\b/,
        /\bprepaid cards?\b/,
        /\bscratch[- ]off\b/,
        /\brecharge (card|voucher)s?\b/,
        /\bvoucher codes?\b/,
        /\b(ebay|walmart|target|tesco) (gift )?(card|voucher)\b/
      ]
    },
    {
      id: 'crypto-or-wire-request',
      category: 'payment',
      title: 'Cryptocurrency or wire-transfer payment request',
      weight: 12,
      why: 'Cryptocurrency and wire transfers move money instantly and are very hard to reverse, which is why fraudsters push for them.',
      tip: 'If you are asked to send money by crypto or wire to an account you cannot independently verify, stop and check with a colleague or your bank.',
      patterns: [
        /\b(wire transfer|bank transfer|money transfer)\b/,
        /\bbitcoin\b/,
        /\bbit ?coin (address|wallet)\b/,
        /\bcrypto ?(currency|wallet|payment)\b/,
        /\busdt\b/,
        /\bethereum\b/,
        /\bwestern union\b/,
        /\bmoneygram\b/,
        /\bxrp\b|\bbtc (address|wallet)\b/
      ]
    },
    {
      id: 'card-details-request',
      category: 'payment',
      title: 'Request for card or payment details',
      weight: 12,
      why: 'Card numbers, expiry dates and security codes (CVV) are enough to make online purchases. Genuine companies never ask for them by email.',
      tip: 'Do not type card details into any page reached from an email link.',
      patterns: [
        /\b(confirm|update|verify|provide|send|enter|validate) (us )?(your )?(credit card|debit card|card|billing|payment|bank) (details|information|number|data)\b/,
        /\bcard ?number\b/,
        /\b(cvv|cvc|cvv2|security code on) (number|code)?\b/,
        /\bfull card details\b/,
        /\bexpiry date\b/,
        /\baccount number\b/,
        /\bsort code\b/,
        /\brouting number\b/,
        /\biban\b/,
        /\bswift (code|bic)\b/
      ]
    },
    {
      id: 'advance-fee-lure',
      category: 'payment',
      title: 'Too-good-to-be-true offer (advance-fee lure)',
      weight: 12,
      why: 'Winning a prize you never entered, or being offered a share of unclaimed money, is a classic lure used to obtain a "release fee", your bank details, or your identity documents.',
      tip: 'You cannot win a competition you never entered.',
      patterns: [
        /\b(you (have|'ve) won|you are a winner|winner of)\b/,
        /\bcongratulations?[^.]{0,40}\b(won|winner|selected|lucky)\b/,
        /\blottery\b/,
        /\bsweepstake\b/,
        /\bunclaimed (funds|money|inheritance)\b/,
        /\binheritance\b/,
        /\bnext of kin\b/,
        /\bbeneficiary of\b/,
        /\bclaim (your|the) (prize|funds|money|reward)\b/,
        /\brelease fee\b/,
        /\bprocessing fee\b/,
        /\bcustoms (fee|charge|duty)\b/
      ]
    },
    {
      id: 'delivery-fee-request',
      category: 'payment',
      title: 'Small "delivery" or "redelivery" fee',
      weight: 8,
      why: 'Parcel-delivery scams ask for a small fee for a parcel that was never really held. The amount is tiny on purpose - it only needs to be big enough to capture your card details.',
      tip: 'Track a parcel only on the courier\'s own website using the reference number you already had.',
      patterns: [
        /\b(re-?delivery|reschedule|rescheduling) (fee|charge|payment)\b/,
        /\bsmall (delivery|shipping|handling) (fee|charge|payment)\b/,
        /\bcustoms (fee|charge|duty)\b/,
        /\bpay (a|the|just) .{0,20}\b(shipping|delivery|postage|handling)\b/,
        /\bfailed delivery\b/,
        /\bmissed delivery\b/,
        /\bcould not be delivered\b/,
        /\byour parcel is (waiting|held|on hold)\b/,
        /\btracking number\b[^.]{0,60}\b(fee|payment|pay)\b/
      ]
    },

    /* ---------- Invoices and bank-detail changes (BEC) ---------- */
    {
      id: 'bank-detail-change',
      category: 'bec',
      title: 'Request to change bank or payment details',
      weight: 15,
      why: 'Changing payment details is the heart of business email compromise. A message that "updates" an account number quietly redirects a legitimate payment into the fraudster\'s account.',
      tip: 'Always confirm a change of bank details by phone with a person you already know, using a number from your own records - never a number from the email.',
      patterns: [
        /\b(updated|new|changed|revised|amended|corrected) (our |your |the )?(bank|payment|remittance|wire|account|payee|direct debit) (details|information|instructions|account|number)\b/,
        /\bchange of bank details\b/,
        /\bnew (account number|bank account|payee|beneficiary)\b/,
        /\bremittance (details|advice|information) (have )?(change|chang)d?\b/,
        /\bpayment instructions (have )?(change|chang)d?\b/,
        /\buse (the|our|these|those)? ?(new|following|below|updated) (bank|account|payment|payee) (details|information|number)\b/,
        /\bplease (update|amend|change) (our|your|the) (bank|payment|account) (details|records)\b/,
        /\bfrom now on[, ]+please (pay|send|remit)\b/,
        /\b(direct debit|standing order) (has )?(chang|updat)ed\b/,
        /\bbeneficiary (name|account) (has )?(chang|updat)ed\b/
      ]
    },
    {
      id: 'invoice-language',
      category: 'bec',
      title: 'Unexpected invoice, purchase or payment language',
      weight: 12,
      why: 'Attackers attach a fake invoice and rely on it being paid without question. If you were not expecting an invoice, treat the attachment as hostile.',
      tip: 'Check any invoice against the supplier\'s own records and the purchase order you already have.',
      patterns: [
        /\binvoice (is )?(attached|enclosed|below|#|number|no\.?|ref)\b/,
        /\bsee (the )?attached invoice\b/,
        /\bpurchase order (attached|is attached|number)\b/,
        /\boutstanding (balance|invoice|payment|amount|sum)\b/,
        /\boverdue (invoice|payment|balance|account)\b/,
        /\bremittance\b/,
        /\bstatement (is )?attached\b/,
        /\bpayment (is )?due\b/,
        /\byour (payment|order|invoice|subscription) of [\u00a3$€]?\d/,
        /\bamount due\b/,
        /\bfinal demand\b/,
        /\bdebt collection\b/,
        /\bpro forma invoice\b/,
        /\bswift (copy|confirmation) (attached|enclosed)\b/
      ]
    },
    {
      id: 'secrecy-request',
      category: 'bec',
      title: 'Request for secrecy or confidentiality',
      weight: 10,
      why: 'Fraudsters ask you to keep a payment or request confidential so that nobody in finance, IT or management can question it. Legitimate business requests never need secrecy.',
      tip: 'Secrecy plus money is one of the clearest signs of fraud. Tell a colleague or your manager.',
      patterns: [
        /\bkeep (this|it) (confidential|between us|quiet|private|secret)\b/,
        /\bdo not (discuss|tell|share|mention) (this|it) with (anyone|anybody|others|staff|colleagues)\b/,
        /\bdon'?t (tell|inform|mention|discuss) (anyone|anybody|others|the team|your colleagues)\b/,
        /\bthis (email|message|request) is (strictly )?confidential\b/,
        /\bstrictly confidential\b/,
        /\bhandle this (personally|discreetly)\b/,
        /\bnot (to be )?(discussed|shared) (with|in)\b/
      ]
    },

    /* ---------- Links: call-to-action wording ---------- */
    {
      id: 'link-cta-language',
      category: 'links',
      title: 'Pushy call-to-action wording ("click here")',
      weight: 8,
      why: 'Phishing emails need you to click. Phrases that push the click - and hide the destination - are a hallmark of fraudulent mail.',
      tip: 'Hover over a link (or press and hold on a phone) before you click, and read the real address.',
      patterns: [
        /\bclick (here|this link|the link|below|now)\b/,
        /\bfollow (this|the) link\b/,
        /\bclick (on )?(the )?link below\b/,
        /\bopen the (link|attachment|attached file|attached document|invoice)\b/,
        /\buse the link below\b/,
        /\baccess your (account|portal|dashboard) (here|below)\b/,
        /\bdownload the (document|file|invoice|attachment) here\b/
      ]
    },

    /* ---------- Attachments: instructions that make them dangerous ---------- */
    {
      id: 'enable-macro-request',
      category: 'attachments',
      title: 'Request to enable macros or editing content',
      weight: 12,
      why: 'Macros are small programs. When a document asks you to "enable content", you are being asked to let the attached file run code on your computer. This is one of the most common ways malware is installed.',
      tip: 'Never enable macros or editing content in a document you were not expecting.',
      patterns: [
        /\benable (macros?|editing|content|active content)\b/,
        /\bmacros? (must|need|should|have) (to )?be (enabled|allowed|turned on)\b/,
        /\bclick (enable|allow|yes) (content|editing|macros)\b/,
        /\b(macros?|content) (is|are) (currently )?disabled\b/,
        /\bview (tab|ribbon|menu)[^.]{0,40}\benable\b/,
        /\bprotected view\b/,
        /\byou (must|need to) enable\b/,
        /\b(allow|enable) (the )?(document|file) to (run|update|load)\b/
      ]
    },

    /* ---------- Impersonation wording ---------- */
    {
      id: 'generic-greeting',
      category: 'impersonation',
      title: 'Generic or impersonal greeting',
      weight: 6,
      why: 'Bulk phishing rarely knows your name, so it uses "Dear Customer" or "Dear User". Most legitimate organisations you have an account with know who you are.',
      tip: 'This is a weak signal on its own - it matters most when other warning signs are present.',
      patterns: [
        /\bdear (customer|user|client|member|valued customer|account holder|sir\/madam|sir or madam|email user|email owner|friend|beneficiary)\b/,
        /\bdear (customer )?(of|from) (microsoft|apple|google|amazon|paypal|netflix|amazon\.com|paypal\.com)\b/,
        /\bhello (dear )?(customer|user|client|member|sir\/madam)\b/,
        /\bto (our )?valued (customer|client|member)s?\b/,
        /\bdear account holder\b/
      ],
      /* If a real name follows, it is not a generic greeting. */
      unless: [
        /\bdear (mr|mrs|ms|miss|dr|prof)\.? [a-z]+/,
        /\bdear [A-Z][a-z]+ [A-Z][a-z]+\b/
      ]
    },
    {
      id: 'impersonation-language',
      category: 'impersonation',
      title: 'Language that borrows authority (IT, security team, senior staff)',
      weight: 8,
      why: 'Attackers write as "the IT department", "the security team" or a senior executive so that the request feels authorised and urgent.',
      tip: 'Verify requests from any internal department using a channel you already trust.',
      patterns: [
        /\b(it|i\.t\.|security|help ?desk|service desk|support|technical) (team|department|desk|centre|center|administrator|admin)\b/,
        /\bon behalf of\b/,
        /\bfrom the (ceo|cfo|coo|cio|cto|director|managing director|chairman|chief executive|chief financial)\b/,
        /\b(your )?(system|email|network|mail) administrator\b/,
        /\b(mail|mailbox|server|account) administrator\b/,
        /\bwe (have )?(noticed|detected|observed|identified) (unusual|suspicious|unrecognized|unrecognised|unauthorized|unauthorised|abnormal|unexpected)\b/,
        /\b(our|the) (records|system|systems|security) (show|shows|indicate|indicates|confirm)\b/,
        /\bunusual (sign[- ]?in|login|log[- ]?in|activity|access) (attempt|activity|was|from)\b/,
        /\bnew (device|browser) (signed|has signed) in\b/,
        /\bthis is (the )?(it|security|admin) (department|team)\b/,
        /\bacting on (behalf of|instructions from)\b/
      ]
    },

    ];  /* end of PHRASE_RULES */

  /* ========================================================================
     3b. HELPER FUNCTIONS (shared by the custom rules below)
     ======================================================================== */

  /* Split a hostname into its parts: "mail.example.co.uk" -> [mail,example,co,uk] */
  function labelsOf(host) {
    return String(host || '').toLowerCase().replace(/\.+$/, '').split('.').filter(Boolean);
  }

  /* The "real" domain of a host, ignoring sub-domains.
     "mail.example.co.uk" -> "example.co.uk";  "a.b.example.com" -> "example.com".
     This matters because attackers put the brand in the sub-domain:
     paypal.com.secure-login.example  (the real domain here is "example"). */
  function registrableDomain(host) {
    var labels = labelsOf(host);
    if (labels.length <= 2) { return labels.join('.'); }
    var lastTwo = labels.slice(-2).join('.');
    if (TWO_PART_SUFFIXES.indexOf(lastTwo) !== -1) { return labels.slice(-3).join('.'); }
    return lastTwo;
  }

  /* Is this host a bare IP address such as 198.51.100.23 ? */
  function isIpHost(host) {
    var h = String(host || '').replace(/^\[|\]$/g, '');
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) {
      return h.split('.').every(function (part) { return Number(part) <= 255; });
    }
    /* IPv6 (contains two or more colons) */
    return /:/.test(h) && /^[0-9a-f:]+$/i.test(h);
  }

  /* Turn "micros0ft", "rnicrosoft" or "paypa1" into "microsoft" / "paypal"
     so we can compare a domain against a genuine brand name. */
  function normalizeLookalike(value) {
    var s = String(value || '').toLowerCase();
    s = s.replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/cl/g, 'd').replace(/ii/g, 'n');
    s = s.replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e').replace(/4/g, 'a')
         .replace(/5/g, 's').replace(/7/g, 't').replace(/8/g, 'b').replace(/9/g, 'g');
    s = s.replace(/[^a-z]/g, '');
    return s.replace(/(.)\1{2,}/g, '$1$1');
  }

  /* Small edit-distance function (how many single-letter changes are needed
     to turn one word into another). Capped at 3 to stay fast. */
  function editDistance(a, b) {
    if (a === b) { return 0; }
    if (Math.abs(a.length - b.length) > 3) { return 4; }
    var prev = [], cur = [], i, j;
    for (j = 0; j <= b.length; j++) { prev[j] = j; }
    for (i = 1; i <= a.length; i++) {
      cur[0] = i;
      for (j = 1; j <= b.length; j++) {
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      }
      prev = cur.slice();
    }
    return prev[b.length];
  }

  /* Find a brand mentioned in some text, e.g. "Microsoft 365" -> Microsoft */
  function findBrand(text) {
    var t = String(text || '').toLowerCase();
    for (var i = 0; i < BRANDS.length; i++) {
      for (var j = 0; j < BRANDS[i].tokens.length; j++) {
        var token = BRANDS[i].tokens[j];
        var idx = t.indexOf(token);
        if (idx === -1) { continue; }
        var before = idx === 0 ? ' ' : t.charAt(idx - 1);
        var after = t.charAt(idx + token.length) || ' ';
        var okBefore = !/[a-z0-9]/.test(before);
        var okAfter = !/[a-z0-9]/.test(after);
        if (okBefore && okAfter) { return BRANDS[i]; }
      }
    }
    return null;
  }

  /* Does this host belong to the brand, either exactly or as a sub-domain? */
  function hostBelongsToBrand(host, brand) {
    var h = String(host || '').toLowerCase();
    var reg = registrableDomain(h);
    return brand.domains.some(function (d) {
      return reg === d || h === d || h.endsWith('.' + d);
    });
  }

  /* Normalise a domain core but KEEP the separators, so that we can tell
     "paypal-secure" (brand plus extra words - suspicious) apart from
     "parcel-redelivery" (which merely happens to contain the letters "live").
     "micros0ft-secure" -> "microsoft-secure". */
  function normalizeWithSeparators(value) {
    var s = String(value || '').toLowerCase()
      .replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/cl/g, 'd').replace(/ii/g, 'n')
      .replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e').replace(/4/g, 'a')
      .replace(/5/g, 's').replace(/7/g, 't').replace(/8/g, 'b').replace(/9/g, 'g')
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '');
    return s;
  }

  /* Is this domain a "look-alike" of a brand domain, e.g. micros0ft.com,
     paypal-secure.example or ups-tracking.example? */
  function findLookalikeBrand(host) {
    var reg = registrableDomain(host);
    var core = reg.split('.')[0] || '';
    var tld = reg.split('.').pop() || '';
    var normalizedCore = normalizeLookalike(core);
    var coreWithSeparators = normalizeWithSeparators(core);
    if (!core || !normalizedCore) { return null; }

    for (var i = 0; i < BRANDS.length; i++) {
      var brand = BRANDS[i];
      if (hostBelongsToBrand(host, brand)) { return null; }

      for (var j = 0; j < brand.domains.length; j++) {
        var brandCore = brand.domains[j].split('.')[0];
        var normalizedBrand = normalizeLookalike(brandCore);
        var brandWithSeparators = normalizeWithSeparators(brandCore);
        if (!normalizedBrand) { continue; }

        /* The same letters, but not the genuine domain: micros0ft, paypa1, rnicrosoft */
        if (normalizedCore === normalizedBrand && core !== brandCore) {
          return { brand: brand, matched: core, expected: brandCore, reason: 'look-alike' };
        }
        /* The brand name followed by extra words, kept apart by a separator:
           paypal-secure, ups-tracking, micros0ft-login. The separator check
           stops innocent words such as "rede-livery" matching "live". */
        var tokenRe = new RegExp('(^|-)' + escapeRegExp(brandWithSeparators) + '($|-)');
        if (coreWithSeparators !== brandWithSeparators && tokenRe.test(coreWithSeparators)) {
          return { brand: brand, matched: core, expected: brandCore, reason: 'brand-plus-extra' };
        }
        /* The brand name used as the whole domain, but on a cheap or
           disposable domain ending: paypal.zip, microsoft.tk */
        if (coreWithSeparators === brandWithSeparators
          && RISKY_TLDS.indexOf(tld) !== -1) {
          return { brand: brand, matched: reg, expected: brandCore, reason: 'brand-as-domain' };
        }
        /* One letter changed, e.g. arnazon.com or paypa1.com */
        if (normalizedBrand.length >= 5 && editDistance(normalizedCore, normalizedBrand) === 1) {
          return { brand: brand, matched: core, expected: brandCore, reason: 'one-letter-change' };
        }
      }
    }
    return null;
  }

  /* Escape a literal string so it can be used inside a regular expression. */
  function escapeRegExp(value) {
    return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  /* Pull the host out of a link address, e.g. "https://a.b.example.com/x" ->
     "a.b.example.com". Used by the link-text-mismatch check. */
  function hostFromHref(href) {
    var h = String(href || '').trim();
    h = h.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
    h = h.split(/[\/?#]/)[0];
    h = h.split('@').pop();
    h = h.replace(/:\d+$/, '');
    return h.toLowerCase();
  }

  /* Find a domain name written inside ordinary text, e.g. the visible text of
     a link: "login.microsoft.com" -> "microsoft.com". Returns null when there
     is no domain-looking word. */
  function extractDomainFromText(text) {
    var t = String(text || '');
    var m = t.match(/\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b/i);
    if (!m) { return null; }
    return registrableDomain(m[1].toLowerCase());
  }

  var HELPERS = {
    labelsOf: labelsOf,
    registrableDomain: registrableDomain,
    isIpHost: isIpHost,
    normalizeLookalike: normalizeLookalike,
    editDistance: editDistance,
    findBrand: findBrand,
    hostBelongsToBrand: hostBelongsToBrand,
    findLookalikeBrand: findLookalikeBrand,
    escapeRegExp: escapeRegExp,
    hostFromHref: hostFromHref,
    extractDomainFromText: extractDomainFromText
  };

  /* ========================================================================
     4. CUSTOM_RULES - checks that need real logic
     -----------------------------------------------------------------------
     Each rule receives a "context" object prepared by js/analyzer.js:
       ctx.text        the pasted text as typed
       ctx.lower       lower-case, tag-stripped version
       ctx.urls        [{ href, host, registrable, path, query, scheme, port,
                          hasUserInfo, isIp }]
       ctx.attachments [{ name, ext, isDoubleExtension, decoyExt, looksOdd }]
       ctx.anchors     [{ text, href }]  - link text and its real destination
       ctx.headerInfo  parsed sender and authentication information
       ctx.helpers     the helper functions defined above
     A rule returns null (not triggered) or { evidence: '...', note: '...' }.
     ======================================================================== */
  var CUSTOM_RULES = [

    /* ---------- Link checks ---------- */
    {
      id: 'url-raw-ip',
      category: 'links',
      title: 'Link uses a raw IP address instead of a domain name',
      weight: 14,
      why: 'Real companies use readable domain names. A link built on a bare IP address (such as 198.51.100.23) has no brand and often no legitimate reason to be in an email.',
      tip: 'Anything after the address that looks like a brand is decoration - the IP address is where you would really go.',
      test: function (ctx) {
        var hits = ctx.urls.filter(function (u) { return u.isIp; });
        if (!hits.length) { return null; }
        return { evidence: 'Link host is an IP address: ' + hits[0].host };
      }
    },
    {
      id: 'url-shortener',
      category: 'links',
      title: 'Shortened link hides its destination',
      weight: 8,
      why: 'Link shorteners replace a long address with a short one. That is convenient - and it means you cannot see where you are being sent before you click.',
      tip: 'Legitimate senders normally link to their own domain. If you really must know where a short link goes, preview it with a link-expander instead of clicking it.',
      test: function (ctx) {
        var hits = ctx.urls.filter(function (u) {
          return SHORTENERS.indexOf(u.registrable) !== -1
            || SHORTENERS.indexOf(u.host) !== -1
            || DOCUMENTATION_SHORTENERS.indexOf(u.registrable) !== -1;
        });
        if (!hits.length) { return null; }
        return { evidence: 'Shortened link: ' + hits[0].host };
      }
    },
    {
      id: 'url-lookalike-domain',
      category: 'links',
      title: 'Look-alike domain imitating a known brand',
      weight: 14,
      why: 'Attackers register domains that read like a real brand but are not it - a zero instead of an "o" (micros0ft), an extra word (paypal-secure), or one letter changed. At a glance it looks right.',
      tip: 'Read domain names letter by letter, right to left. The important part is the last two sections before the first single slash.',
      test: function (ctx) {
        var hits = ctx.urls.map(function (u) { return { url: u, match: findLookalikeBrand(u.host) }; })
          .filter(function (x) { return x.match; });
        if (!hits.length) { return null; }
        var m = hits[0].match;
        var reasonText = {
          'look-alike': 'uses look-alike characters',
          'brand-plus-extra': 'adds extra words to a brand name',
          'brand-as-domain': 'uses the brand name with a cheap or disposable domain ending',
          'one-letter-change': 'differs from the real domain by one letter'
        }[m.reason] || 'resembles a brand';
        return { evidence: '"' + m.matched + '" ' + reasonText + ' (real ' + m.brand.name + ' domains end in ' + m.expected + ')' };
      }
    },
    {
      id: 'url-brand-in-subdomain',
      category: 'links',
      title: 'Brand name buried inside a sub-domain',
      weight: 12,
      why: 'In paypal.com.secure-login.example the real domain is "example" - the "paypal.com" part is only a sub-domain invented to fool you. Read left to right, it looks genuine.',
      tip: 'The domain that owns the page is the part immediately before the first single "/".',
      test: function (ctx) {
        for (var i = 0; i < ctx.urls.length; i++) {
          var u = ctx.urls[i];
          var labels = ctx.helpers.labelsOf(u.host);
          var regLabels = ctx.helpers.labelsOf(u.registrable);
          var subLabels = labels.slice(0, Math.max(0, labels.length - regLabels.length));
          if (!subLabels.length) { continue; }
          for (var j = 0; j < BRANDS.length; j++) {
            if (hostBelongsToBrand(u.host, BRANDS[j])) { break; }
            for (var k = 0; k < BRANDS[j].tokens.length; k++) {
              var token = BRANDS[j].tokens[k];
              if (token.length < 4 || token.indexOf(' ') !== -1) { continue; }
              if (subLabels.indexOf(token) !== -1) {
                return { evidence: '"' + BRANDS[j].name + '" appears before the real domain "' + u.registrable + '" in ' + u.host };
              }
            }
          }
        }
        return null;
      }
    },

    {
      id: 'url-userinfo-trick',
      category: 'links',
      title: 'Link uses the "@" trick to fake the destination',
      weight: 10,
      why: 'In a web address, everything before an "@" is treated as a username and ignored by the browser. A link reading https://accounts.google.com@evil.example actually goes to evil.example.',
      tip: 'If you see an "@" sign in a link, read only the part that comes after it.',
      test: function (ctx) {
        var hits = ctx.urls.filter(function (u) {
          return u.hasUserInfo || /@/.test(u.href.replace(/^[a-z]+:\/\//i, '').split('/')[0]);
        });
        if (!hits.length) { return null; }
        return { evidence: 'Contains "@" before the real host: ' + hits[0].href.slice(0, 90) };
      }
    },
    {
      id: 'url-punycode',
      category: 'links',
      title: 'Internationalised (punycode) domain name',
      weight: 12,
      why: 'Domains starting with "xn--" use characters that can look identical to Latin letters - for example a Cyrillic "a" instead of an English "a". The address looks right and is not.',
      tip: '"xn--" means the domain contains non-English characters. Be very cautious unless you expected it.',
      test: function (ctx) {
        var hits = ctx.urls.filter(function (u) { return /(^|\.)xn--/i.test(u.host); });
        if (!hits.length) { return null; }
        return { evidence: 'Punycode domain: ' + hits[0].host };
      }
    },
    {
      id: 'url-risky-tld',
      category: 'links',
      title: 'Domain ending commonly used for disposable malicious sites',
      weight: 8,
      why: 'Some domain endings are extremely cheap or free, so fraudsters register thousands at a time. Those endings appear in phishing far more often than their share of the internet would suggest.',
      tip: 'A cheap ending proves nothing by itself - treat it as one more warning sign.',
      test: function (ctx) {
        var hits = ctx.urls.filter(function (u) {
          var labels = ctx.helpers.labelsOf(u.host);
          return RISKY_TLDS.indexOf(labels[labels.length - 1]) !== -1;
        });
        if (!hits.length) { return null; }
        var labels = ctx.helpers.labelsOf(hits[0].host);
        return { evidence: 'Uses the domain ending ".' + labels[labels.length - 1] + '": ' + hits[0].host };
      }
    },
    {
      id: 'url-credential-path',
      category: 'links',
      title: 'Link leads to a sign-in or account path',
      weight: 6,
      why: 'Fake sign-in pages are usually placed at /login, /verify, /secure or similar paths so that the address looks convincing when you finally see it.',
      tip: 'Sign in by opening your browser and typing the company\'s address yourself.',
      test: function (ctx) {
        for (var i = 0; i < ctx.urls.length; i++) {
          var path = (ctx.urls[i].path || '').toLowerCase();
          for (var j = 0; j < CREDENTIAL_PATH_WORDS.length; j++) {
            if (path.indexOf(CREDENTIAL_PATH_WORDS[j]) !== -1) {
              return { evidence: 'Link path contains "' + CREDENTIAL_PATH_WORDS[j] + '": ' + ctx.urls[i].host + ctx.urls[i].path };
            }
          }
        }
        return null;
      }
    },
    {
      id: 'url-redirect-parameter',
      category: 'links',
      title: 'Link contains another web address inside it (redirect)',
      weight: 6,
      why: 'Putting a second address inside a link lets a genuine-looking address forward you somewhere else. It is a common way to get past link filters.',
      tip: 'If the address contains another full "http" in the middle, expect to be forwarded somewhere else.',
      test: function (ctx) {
        var hits = ctx.urls.filter(function (u) {
          var afterHost = u.href.replace(/^[a-z]+:\/\//i, '').split('/').slice(1).join('/');
          return /https?(:|%3a)(\/\/|%2f%2f)/i.test(afterHost);
        });
        if (!hits.length) { return null; }
        return { evidence: 'Second address inside the link: ' + hits[0].href.slice(0, 90) };
      }
    },
    {
      id: 'url-nonstandard-port',
      category: 'links',
      title: 'Link uses an unusual port number',
      weight: 6,
      why: 'Normal websites run on port 80 (http) or 443 (https), which are not usually shown. An address with an odd port such as :8080 or :8443 is usually a directly-hosted fraud site.',
      tip: 'Ordinary websites never need you to type an explicit port number.',
      test: function (ctx) {
        var hits = ctx.urls.filter(function (u) {
          return u.port && u.port !== '80' && u.port !== '443';
        });
        if (!hits.length) { return null; }
        return { evidence: 'Link uses port ' + hits[0].port + ': ' + hits[0].host };
      }
    },
    {
      id: 'link-text-mismatch',
      category: 'links',
      title: 'Link text does not match the real destination',
      weight: 10,
      why: 'The words you see can be completely different from where the link goes. Attackers write "login.microsoft.com" as the visible text but point the link at their own site.',
      tip: 'Always check the destination, never the label. On a phone, press and hold the link to see the address.',
      test: function (ctx) {
        for (var i = 0; i < ctx.anchors.length; i++) {
          var a = ctx.anchors[i];
          var visibleDomain = extractDomainFromText(a.text);
          if (!visibleDomain) { continue; }
          var realDomain = ctx.helpers.registrableDomain(hostFromHref(a.href));
          if (!realDomain) { continue; }
          if (visibleDomain !== realDomain) {
            return { evidence: 'Text says "' + visibleDomain + '" but the link really points to "' + realDomain + '"' };
          }
        }
        return null;
      }
    },

    /* ---------- Attachment checks ---------- */
    {
      id: 'attachment-executable',
      category: 'attachments',
      title: 'Executable or script attachment',
      weight: 20,
      why: 'Files such as .exe, .scr, .js, .vbs, .bat, .cmd, .ps1, .lnk, .hta, .jar, .iso and .dll can run code when opened. An unexpected program arriving by email is one of the most common ways malware is delivered.',
      tip: 'Never open an unexpected executable or script file - even from somebody you know, because their computer may already be infected.',
      test: function (ctx) {
        var hits = ctx.attachments.filter(function (a) { return EXECUTABLE_EXTS.indexOf(a.ext) !== -1; });
        if (!hits.length) { return null; }
        return { evidence: 'Executable/script file: ' + hits[0].name };
      }
    },
    {
      id: 'attachment-macro',
      category: 'attachments',
      title: 'Macro-enabled Office document',
      weight: 12,
      why: 'Documents ending in .docm, .xlsm, .pptm (and older .doc/.xls when macros are discussed) are allowed to contain macros - small programs that can download and run malware.',
      tip: 'Ask yourself why an invoice or CV needs a program inside it. If the sender is genuine, ask them to send a PDF instead.',
      test: function (ctx) {
        var hits = ctx.attachments.filter(function (a) { return MACRO_EXTS.indexOf(a.ext) !== -1; });
        if (!hits.length) {
          /* Older formats only matter when the message talks about macros. */
          var legacy = ctx.attachments.filter(function (a) { return LEGACY_OFFICE_EXTS.indexOf(a.ext) !== -1; });
          var macroTalk = /\b(macro|enable content|enable editing|enable macros)\b/i.test(ctx.lower);
          if (legacy.length && macroTalk) {
            return { evidence: 'Legacy Office file with macro instructions: ' + legacy[0].name };
          }
          return null;
        }
        return { evidence: 'Macro-enabled document: ' + hits[0].name };
      }
    },
    {
      id: 'attachment-double-extension',
      category: 'attachments',
      title: 'File uses a double extension to look harmless',
      weight: 14,
      why: 'Windows decides what a file is from its last extension. "Invoice.pdf.exe" is a program that often shows a PDF-style icon - your computer may even hide the final ".exe" from you.',
      tip: 'Turn on file-name extensions in your operating system so you can always see the true ending.',
      test: function (ctx) {
        var hits = ctx.attachments.filter(function (a) { return a.isDoubleExtension; });
        if (!hits.length) { return null; }
        return { evidence: 'Double extension: ' + hits[0].name };
      }
    },
    {
      id: 'attachment-archive-with-password',
      category: 'attachments',
      title: 'Archive attachment, with a password mentioned in the message',
      weight: 10,
      why: 'Password-protected archives hide their contents from email and antivirus scanners. The password is only ever put in the message so that you - and not the security software - can open it.',
      tip: 'Legitimate senders who need to password-protect a file will usually tell you the password another way.',
      test: function (ctx) {
        var archives = ctx.attachments.filter(function (a) { return ARCHIVE_EXTS.indexOf(a.ext) !== -1; });
        if (!archives.length) { return null; }
        var passwordTalk = /\b(password|passphrase|passcode|protected|unlock)\b[^.]{0,40}\b(zip|archive|attachment|file|document|rar|7z)\b/i.test(ctx.lower)
          || /\b(zip|archive|rar|7z|attachment|file|document)\b[^.]{0,40}\b(password|passphrase|passcode|is protected)\b/i.test(ctx.lower);
        if (!passwordTalk) { return null; }
        return { evidence: 'Archive attachment with a password in the message: ' + archives[0].name };
      }
    },
    {
      id: 'attachment-html',
      category: 'attachments',
      title: 'Web page (.html) sent as an attachment',
      weight: 6,
      why: 'An attached web page opens locally in your browser and can display a perfect copy of a real sign-in form. Anything you type into it goes straight to the attacker.',
      tip: 'Banks and large companies do not send you their sign-in page as an attachment.',
      test: function (ctx) {
        var hits = ctx.attachments.filter(function (a) { return HTML_EXTS.indexOf(a.ext) !== -1; });
        if (!hits.length) { return null; }
        return { evidence: 'Web page attachment: ' + hits[0].name };
      }
    },
    {
      id: 'attachment-unusual-filename',
      category: 'attachments',
      title: 'Unusual or suspicious attachment filename',
      weight: 6,
      why: 'Very long filenames, many dots, mixed scripts or a name that does not match the message ("scan_2024_final_final.pdf" for an invoice) are all signs of a mass-produced scam attachment.',
      tip: 'Judge the filename against what the email claims the file is.',
      test: function (ctx) {
        var hits = ctx.attachments.filter(function (a) { return a.looksOdd; });
        if (!hits.length) { return null; }
        return { evidence: 'Unusual filename: ' + hits[0].name, note: hits[0].oddReason || '' };
      }
    },

    /* ---------- Header-based checks (only when headers are pasted) ---------- */
    {
      id: 'header-replyto-mismatch',
      category: 'headers',
      title: 'Reply-To or Return-Path address points somewhere else',
      weight: 14,
      why: 'If replies go to a different domain from the one shown as the sender, somebody is intercepting your answer. Fraudsters point replies at an address they control so the conversation continues with them instead of the real organisation.',
      tip: 'Check the real sender address, not just the display name, before you reply.',
      test: function (ctx) {
        var info = ctx.headerInfo;
        if (!info || !info.present || !info.from || !info.from.domain) { return null; }
        var fromReg = ctx.helpers.registrableDomain(info.from.domain);
        var problems = [];
        if (info.replyTo && info.replyTo.domain) {
          var replyReg = ctx.helpers.registrableDomain(info.replyTo.domain);
          if (replyReg && replyReg !== fromReg) {
            problems.push('replies go to ' + info.replyTo.address + ' (a different domain)');
          }
        }
        if (info.returnPath && info.returnPath.domain) {
          var rpReg = ctx.helpers.registrableDomain(info.returnPath.domain);
          if (rpReg && rpReg !== fromReg) {
            problems.push('the Return-Path domain is ' + rpReg + ' instead of ' + fromReg);
          }
        }
        if (!problems.length) { return null; }
        return { evidence: 'From domain "' + fromReg + '", but ' + problems.join('; ') };
      }
    },
    {
      id: 'header-spf-fail',
      category: 'headers',
      title: 'SPF check failed',
      weight: 12,
      why: 'SPF is a list, published by the domain owner, of which servers are allowed to send mail for that domain. A failure means the message came from a server the domain has not authorised - which is normal for a forged sender.',
      tip: 'SPF is evidence, not proof: forwarding and mailing lists can also cause SPF failures.',
      test: function (ctx) {
        var info = ctx.headerInfo;
        if (!info || !info.auth) { return null; }
        if (info.auth.spf === 'fail' || info.auth.spf === 'softfail') {
          return { evidence: 'Authentication-Results reports spf=' + info.auth.spf };
        }
        return null;
      }
    },
    {
      id: 'header-dkim-fail',
      category: 'headers',
      title: 'DKIM signature failed or missing',
      weight: 10,
      why: 'DKIM is a cryptographic signature proving that the message really came from the domain that claims to have sent it, and that it was not altered on the way.',
      tip: 'DKIM can legitimately break when a message is forwarded or rewritten by a mailing list.',
      test: function (ctx) {
        var info = ctx.headerInfo;
        if (!info || !info.auth || !info.present) { return null; }
        if (info.auth.dkim === 'fail' || info.auth.dkim === 'temperror' || info.auth.dkim === 'permerror') {
          return { evidence: 'Authentication-Results reports dkim=' + info.auth.dkim };
        }
        if (info.auth.dkim === 'none') {
          return { evidence: 'No DKIM signature was found for this message' };
        }
        return null;
      }
    },
    {
      id: 'header-dmarc-fail',
      category: 'headers',
      title: 'DMARC check failed',
      weight: 12,
      why: 'DMARC is the domain owner\'s standing instruction to receiving mail systems: "if a message claiming to be from me fails SPF or DKIM, treat it as a forgery". A DMARC failure is one of the strongest technical signals of spoofing.',
      tip: 'When it is present, take it seriously - but it can be affected by forwarding too.',
      test: function (ctx) {
        var info = ctx.headerInfo;
        if (!info || !info.auth) { return null; }
        if (info.auth.dmarc === 'fail') {
          return { evidence: 'Authentication-Results reports dmarc=fail' };
        }
        return null;
      }
    },
    {
      id: 'header-displayname-brand-mismatch',
      category: 'impersonation',
      title: 'Display name claims a brand the sending domain does not own',
      weight: 12,
      why: 'The friendly name in an email ("Microsoft 365") is written by the sender and can say anything at all. What cannot be faked so easily is the domain after the "@" in the real address.',
      tip: 'Always read the full address, e.g. "Microsoft 365 <alerts@example-mail.example>", and not just the friendly name.',
      test: function (ctx) {
        var info = ctx.headerInfo;
        if (!info || !info.present || !info.from) { return null; }
        var brand = findBrand(info.from.display || '');
        if (!brand || !info.from.domain) { return null; }
        if (hostBelongsToBrand(info.from.domain, brand)) { return null; }
        return { evidence: 'Display name says "' + String(info.from.display || '').trim() + '" but the address is ' + info.from.address };
      }
    },

    /* ---------- Obfuscation checks ---------- */
    {
      id: 'obfuscation-invisible-characters',
      category: 'obfuscation',
      title: 'Invisible or text-direction control characters',
      weight: 6,
      why: 'Zero-width and bidirectional control characters are invisible on screen but are read by computers. Attackers use them to break keyword filters and to make a filename or address look different from what it really is.',
      tip: 'Pasting the text into a plain-text editor is one way to reveal them.',
      test: function (ctx) {
        var re = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD]/g;
        var found = ctx.text.match(re);
        if (!found) { return null; }
        return { evidence: found.length + ' invisible control character(s) found in the message text' };
      }
    },
    {
      id: 'obfuscation-letter-spacing',
      category: 'obfuscation',
      title: 'Words broken up with spaces to defeat filters',
      weight: 6,
      why: 'Writing "c l i c k" or "p a s s w o r d" hides a trigger word from automated filters while your brain still reads it normally. There is no legitimate reason to do this.',
      tip: 'This trick is used almost exclusively by spam and phishing.',
      test: function (ctx) {
        var words = ctx.text.match(/[A-Za-z](?:\s[A-Za-z]){4,}/g) || [];
        for (var i = 0; i < words.length; i++) {
          var squashed = words[i].replace(/\s+/g, '').toLowerCase();
          if (SPACED_WORDS.indexOf(squashed) !== -1) {
            return { evidence: 'Spaced-out word: "' + words[i] + '"' };
          }
        }
        return null;
      }
    },
    {
      id: 'obfuscation-encoded-blob',
      category: 'obfuscation',
      title: 'Large encoded block of text',
      weight: 6,
      why: 'Long blocks of random-looking letters and numbers are usually encoded data. They are used to hide links, scripts or credentials from email filters, and they have no place in an ordinary message.',
      tip: 'Be extra careful with a message containing a wall of meaningless characters.',
      test: function (ctx) {
        var blobs = ctx.text.match(/[A-Za-z0-9+/=]{120,}/g) || [];
        for (var i = 0; i < blobs.length; i++) {
          var blob = blobs[i];
          var digits = (blob.match(/\d/g) || []).length;
          var upper = (blob.match(/[A-Z]/g) || []).length;
          if (blob.length >= 120 && digits >= 8 && upper >= 5) {
            return { evidence: 'Encoded-looking block of ' + blob.length + ' characters' };
          }
        }
        return null;
      }
    }
  ];  /* end of CUSTOM_RULES */

  /* ========================================================================
     5. EXPORTS
     ======================================================================== */
  return {
    CATEGORIES: CATEGORIES,
    PHRASE_RULES: PHRASE_RULES,
    CUSTOM_RULES: CUSTOM_RULES,
    HELPERS: HELPERS,
    DATA: {
      brands: BRANDS,
      shorteners: SHORTENERS,
      executableExts: EXECUTABLE_EXTS,
      macroExts: MACRO_EXTS,
      legacyOfficeExts: LEGACY_OFFICE_EXTS,
      archiveExts: ARCHIVE_EXTS,
      htmlExts: HTML_EXTS,
      decoyExts: DECOY_EXTS,
      riskyTlds: RISKY_TLDS,
      twoPartSuffixes: TWO_PART_SUFFIXES,
      credentialPathWords: CREDENTIAL_PATH_WORDS,
      spacedWords: SPACED_WORDS
    },

    /* The three risk bands. Kept here so the interface and the tests agree. */
    BANDS: [
      { id: 'low', max: 24, label: 'Low Risk', icon: '\u2714',
        summary: 'Little or no evidence of the classic phishing warning signs.' },
      { id: 'suspicious', max: 54, label: 'Suspicious', icon: '\u26A0',
        summary: 'Several warning signs are present. Treat this message with caution.' },
      { id: 'high', max: 100, label: 'High Risk', icon: '\u26D4',
        summary: 'This message strongly matches known phishing and social-engineering patterns.' }
    ],

    /* Turn a score into a band. */
    bandFor: function (score) {
      var bands = [
        { id: 'low', max: 24, label: 'Low Risk', icon: '\u2714',
          summary: 'Little or no evidence of the classic phishing warning signs.' },
        { id: 'suspicious', max: 54, label: 'Suspicious', icon: '\u26A0',
          summary: 'Several warning signs are present. Treat this message with caution.' },
        { id: 'high', max: 100, label: 'High Risk', icon: '\u26D4',
          summary: 'This message strongly matches known phishing and social-engineering patterns.' }
      ];
      for (var i = 0; i < bands.length; i++) {
        if (score <= bands[i].max) { return bands[i]; }
      }
      return bands[bands.length - 1];
    },

    /* Every rule, both kinds, in one list - used to build the "Scoring" tab. */
    allRules: function () {
      return PHRASE_RULES.concat(CUSTOM_RULES);
    }
  };
});