/* ==========================================================================
   Phishing Email Analyser - js/demos.js
   --------------------------------------------------------------------------
   Six completely fictional demonstration emails, so you can learn without
   touching a single real attack.

   SAFETY RULES FOLLOWED IN EVERY EXAMPLE BELOW:
     - Reserved domains only: example.com / example.org / example.net and the
       reserved .example ending. These can never be registered by anybody, so
       they cannot lead anywhere real.
     - Documentation IP addresses only (192.0.2.x, 198.51.100.x, 203.0.113.x).
       These are reserved for textbooks and are not reachable on the internet.
     - The obviously malicious links are written "defanged" (hxxp://...), the
       same convention security analysts use when sharing links. The analyser
       understands this and still checks them, but you cannot accidentally
       click them.
     - No real brand is ever pointed at by a live link. Where a brand name is
       imitated, it is inside a fictional domain such as micros0ft-alerts.example.
   ========================================================================== */
(function (root, factory) {
  'use strict';
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.PEA = root.PEA || {};
    root.PEA.demos = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var DEMOS = [
    {
      id: 'obvious',
      name: 'Obvious phishing',
      tagline: 'Classic "your account will be deleted" threat',
      expectedBand: 'high',
      expectedIndicators: ['account-suspension-threat', 'password-request',
        'mfa-code-request', 'url-raw-ip', 'header-spf-fail', 'header-dmarc-fail'],
      whatToNotice: 'Every lever is pulled at once: fear, a deadline, a password request, a code request and a bare IP address. This is what most real phishing looks like, and why it is usually easy to spot once you know the pattern.',
      text: [
        'Return-Path: <bounce@mail-collector.example>',
        'From: "Microsoft Account Team" <security-alert@micros0ft-alerts.example>',
        'Reply-To: recover@mail-collector.example',
        'To: customer@example.com',
        'Subject: FINAL NOTICE: Your account will be deleted in 24 hours',
        'Date: Mon, 03 Mar 2025 04:12:07 +0000',
        'Authentication-Results: mx.example.net; spf=fail smtp.mailfrom=mail-collector.example;',
        ' dkim=fail header.d=micros0ft-alerts.example;',
        ' dmarc=fail header.from=micros0ft-alerts.example',
        'Message-ID: <20250303041207.7f2a@mail-collector.example>',
        '',
        'Dear Customer,',
        '',
        'We detected unusual sign-in activity on your account. Your account will be suspended',
        'permanently within 24 hours unless you verify your account immediately.',
        '',
        'Click here to sign in and confirm your password. You must enter your password and the',
        'six-digit code we sent to your phone to complete verification.',
        '',
        'If you do not act now, you will lose access to all your files and email without further',
        'notice. Failure to comply may result in legal action.',
        '',
        'Verify now: hxxp://198.51.100.23/secure/verify?session=99213',
        '',
        'Thank you,',
        'Microsoft Account Team'
      ].join('\n')
    },
    {
      id: 'sophisticated',
      name: 'Sophisticated phishing',
      tagline: 'Polite, well written, no typos - only the domain gives it away',
      expectedBand: 'suspicious',
      expectedIndicators: ['url-lookalike-domain', 'credential-harvest-language'],
      whatToNotice: 'There is no shouting, no threat and not a single spelling mistake. The only strong signal is the domain "docusign-review.example", which contains the brand but is not the brand. This is why "it looks professional" is not evidence that an email is safe.',
      text: [
        'From: "Sarah Whitfield" <s.whitfield@example-legal.example>',
        'To: contracts@example.com',
        'Subject: Contract for review before Thursday',
        'Date: Tue, 04 Mar 2025 09:41:52 +0000',
        '',
        'Hello,',
        '',
        'I hope you are well. I have shared the final version of the contract for your review.',
        'We would appreciate your comments as soon as possible, as the signing window expires in',
        '48 hours.',
        '',
        'Please sign in to confirm your identity before you can open the document:',
        '',
        'https://docusign-review.example/secure/signin',
        '',
        'Kind regards,',
        'Sarah Whitfield',
        'Contracts Department, Example Legal LLP'
      ].join('\n')
    },

    {
      id: 'm365',
      name: 'Fake Microsoft 365 account warning',
      tagline: 'Display name says Microsoft; the address is somebody else',
      expectedBand: 'high',
      expectedIndicators: ['header-displayname-brand-mismatch', 'header-spf-fail',
        'header-dmarc-fail', 'mfa-code-request', 'url-shortener'],
      whatToNotice: 'The friendly name ("Microsoft 365") is just free text the sender typed - it proves nothing. Read the part after the "@": microsoft-365-alerts.example is not Microsoft. The SPF and DMARC failures say the same thing in technical language: this did not come from Microsoft.',
      text: [
        'Return-Path: <bounce@mail-relay.example>',
        'From: "Microsoft 365" <no-reply@microsoft-365-alerts.example>',
        'Reply-To: account-review@mail-relay.example',
        'To: alex.morgan@example.com',
        'Subject: Unusual sign-in activity - action required',
        'Date: Wed, 05 Mar 2025 02:07:44 +0000',
        'Authentication-Results: mx.example.net; spf=fail smtp.mailfrom=mail-relay.example;',
        ' dkim=pass header.d=microsoft-365-alerts.example;',
        ' dmarc=fail header.from=microsoft-365-alerts.example',
        'X-Originating-IP: [203.0.113.47]',
        '',
        'Unusual sign-in activity',
        '',
        'We noticed unusual sign-in activity on your Microsoft 365 account from an unrecognised',
        'device. If this was not you, please sign in immediately and confirm your identity.',
        '',
        'You will be asked for the verification code sent to your phone so we can be sure it is you.',
        '',
        'Review activity: hxxp://link.example/r/9f2a4c',
        '',
        'If you do not confirm within 24 hours your mailbox will be locked.',
        '',
        'Microsoft 365 Security Team'
      ].join('\n')
    },
    {
      id: 'parcel',
      name: 'Fake parcel-delivery message',
      tagline: 'Missed delivery and a tiny "redelivery" fee',
      expectedBand: 'suspicious',
      expectedIndicators: ['delivery-fee-request', 'credential-harvest-language',
        'attachment-html'],
      whatToNotice: 'A small fee is asked for on purpose: it only needs to be big enough for you to type in your card details. Notice the sender and the link have nothing to do with any real courier - the "poorly written mass email" of 2015 has become a polished template.',
      text: [
        'From: "Parcel Notifications" <no-reply@parcel-redelivery.example>',
        'To: recipient@example.com',
        'Subject: Your parcel could not be delivered (ref PD-8842-119)',
        'Date: Thu, 06 Mar 2025 07:14:03 +0000',
        '',
        'Dear Customer,',
        '',
        'Our courier attempted to deliver your parcel today but there was nobody available to sign',
        'for it. Tracking reference: PD-8842-119.',
        '',
        'A small redelivery fee of 1.99 GBP is required to reschedule your delivery. The parcel will',
        'be returned to sender if the fee is not paid within 48 hours.',
        '',
        'Reschedule your delivery and confirm your details here:',
        'https://parcel-redelivery.example/track/PD-8842-119',
        '',
        'We have also attached a copy of the delivery note (delivery-note.html) showing the',
        'attempted delivery time.',
        '',
        'Thank you,',
        'Parcel Notifications Team'
      ].join('\n')
    },

    {
      id: 'bec',
      name: 'Fake invoice / bank-detail change (BEC)',
      tagline: 'A real-looking invoice that quietly redirects a payment',
      expectedBand: 'high',
      expectedIndicators: ['bank-detail-change', 'invoice-language', 'secrecy-request',
        'enable-macro-request', 'attachment-macro', 'header-replyto-mismatch'],
      whatToNotice: 'There is nothing dramatic here at all - this is how business email compromise steals money. Note three things: the bank details "change", the request for secrecy (which stops anyone checking), and replies going to a different domain from the sender. The .docm attachment can only carry this off if somebody enables macros.',
      text: [
        'Return-Path: <bounce@mail-relay.example>',
        'From: "Daniel Okafor (Finance Director)" <d.okafor@example-finance.example>',
        'Reply-To: accounts.payable@mail-relay.example',
        'To: accounts@example.com',
        'Subject: Invoice INV-4471 - updated bank details',
        'Date: Fri, 07 Mar 2025 16:22:19 +0000',
        'Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=mail-relay.example;',
        ' dkim=pass header.d=example-finance.example; dmarc=none',
        '',
        'Hi Alex,',
        '',
        'See attached invoice INV-4471 for 18,450.00 GBP, which is now overdue.',
        '',
        'We have updated our bank details. Please use the new account details below for this',
        'invoice and all future payments:',
        '',
        'Bank: Example Bank PLC',
        'Account name: Example Supplies Ltd',
        'Account number: 00000000',
        'Sort code: 00-00-00',
        'IBAN: GB00EXMP00000000000000',
        '',
        'Please arrange the wire transfer by Friday and keep this confidential until the payment',
        'has cleared.',
        '',
        'The attached document requires you to enable editing and content to view the updated',
        'payment details. Remittance_Advice_INV-4471.docm',
        '',
        'Kind regards,',
        'Daniel Okafor',
        'Finance Director, Example Supplies Ltd'
      ].join('\n')
    },
    {
      id: 'legitimate',
      name: 'Legitimate email (control example)',
      tagline: 'An ordinary message that should score zero',
      expectedBand: 'low',
      expectedIndicators: [],
      whatToNotice: 'This is a "control" example. Nothing about a normal internal message should look like phishing - no pressure, no credential request, no redirect, and the headers pass every authentication check. If your analyser flagged this, the rules would be too eager and you would quickly stop trusting it.',
      text: [
        'Return-Path: <priya.raman@example.com>',
        'From: "Priya Raman" <priya.raman@example.com>',
        'Reply-To: priya.raman@example.com',
        'To: alex.morgan@example.com',
        'Subject: Meeting notes from this morning',
        'Date: Mon, 10 Mar 2025 14:03:11 +0000',
        'Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=example.com;',
        ' dkim=pass header.d=example.com; dmarc=pass header.from=example.com',
        'Message-ID: <b71c2f19@example.com>',
        '',
        'Hi Alex,',
        '',
        'Thanks for your time in the awareness session this morning - the questions were useful.',
        '',
        'I have attached the meeting notes (awareness-notes-week-12.pdf). The training schedule',
        'is on the intranet here:',
        'https://intranet.example.com/training/schedule',
        '',
        'Nothing needed from you before Friday. Shout if you would like anything added.',
        '',
        'Best regards,',
        'Priya Raman',
        'Cyber Awareness Lead, Example Corp'
      ].join('\n')
    }
  ];

  return { demos: DEMOS };
});