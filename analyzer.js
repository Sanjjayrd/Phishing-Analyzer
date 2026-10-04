/* ==========================================================================
   Phishing Email Analyser - js/analyzer.js
   --------------------------------------------------------------------------
   THE ENGINE. This file does three jobs:

     1. PARSING   - turn pasted email text into structured pieces:
                    sender addresses, links, link text, attachment names and
                    email headers (if the user pasted them).
     2. SCORING   - run every rule from rules.js, add up the points, apply the
                    per-category caps and produce a final score out of 100.
     3. EXPLAINING- collect, for every triggered rule, the plain-English reason
                    and the exact piece of text that triggered it.

   Everything happens in memory, in the browser. This file contains no
   network calls of any kind: no fetch, no XMLHttpRequest, no beacons.
   ========================================================================== */
(function (root, factory) {
  'use strict';
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(require('./rules.js'));
  } else {
    root.PEA = root.PEA || {};
    root.PEA.analyzer = factory(root.PEA.rules);
  }
})(typeof self !== 'undefined' ? self : this, function (rules) {
  'use strict';

  var DATA = rules.DATA;
  var HELPERS = rules.HELPERS;

  /* Domain endings used when we are hunting for a domain name inside ordinary
     text (used by the "link text does not match" check). Keeping an explicit
     list stops sentences like "please read the john.smith report" from being
     mistaken for a domain. */
  var KNOWN_TLDS = ['com', 'net', 'org', 'edu', 'gov', 'mil', 'int', 'io', 'co',
    'uk', 'de', 'fr', 'es', 'it', 'nl', 'be', 'ch', 'at', 'se', 'no', 'dk',
    'fi', 'pl', 'cz', 'hu', 'ro', 'gr', 'pt', 'ie', 'ru', 'ua', 'cn', 'jp',
    'kr', 'in', 'au', 'nz', 'ca', 'us', 'br', 'mx', 'za', 'tr', 'il', 'ae',
    'sa', 'sg', 'my', 'hk', 'tw', 'th', 'vn', 'ph', 'id', 'ar', 'cl', 'pe',
    'info', 'biz', 'me', 'tv', 'cc', 'app', 'dev', 'ai', 'cloud', 'tech',
    'online', 'site', 'shop', 'store', 'xyz', 'top'];

  /* Every file extension we know how to reason about. */
  var ALL_ATTACHMENT_EXTS = DATA.executableExts
    .concat(DATA.macroExts, DATA.legacyOfficeExts, DATA.archiveExts, DATA.htmlExts)
    .filter(function (ext, index, list) { return list.indexOf(ext) === index; });

  /* Header names we understand, and how many header lines must be present
     before we believe the user pasted real headers rather than ordinary text. */
  var HEADER_NAMES = ['from', 'to', 'cc', 'bcc', 'subject', 'date', 'reply-to',
    'return-path', 'sender', 'received', 'received-spf', 'authentication-results',
    'arc-authentication-results', 'dkim-signature', 'message-id', 'mime-version',
    'content-type', 'content-transfer-encoding', 'x-mailer', 'x-originating-ip',
    'delivered-to', 'errors-to', 'list-unsubscribe', 'x-spam-score',
    'x-spam-status', 'x-ms-exchange-organization-authas', 'thread-index'];

  /* ------------------------------------------------------------------
     Small text helpers
     ------------------------------------------------------------------ */

  /* Remove HTML tags so we can analyse the words a human would actually see.
     <br> and </p> become line breaks so excerpts stay readable. */
  function stripTags(html) {
    var s = String(html || '');
    s = s.replace(/<script[\s\S]*?<\/script>/gi, ' ');
    s = s.replace(/<style[\s\S]*?<\/style>/gi, ' ');
    s = s.replace(/<br\s*\/?>/gi, '\n');
    s = s.replace(/<\/(p|div|tr|li|h[1-6])>/gi, '\n');
    s = s.replace(/<[^>]+>/g, ' ');
    /* a few common HTML entities */
    s = s.replace(/&nbsp;/gi, ' ').replace(/&amp;/gi, '&')
         .replace(/&lt;/gi, '<').replace(/&gt;/gi, '>')
         .replace(/&quot;/gi, '"').replace(/&#39;/gi, "'");
    s = s.replace(/[ \t]+/g, ' ');
    s = s.replace(/\n{3,}/g, '\n\n');
    return s.trim();
  }

  /* Undo "defanging": analysts deliberately break links when sharing them
     (hxxp://example[.]com). We turn them back into real-looking text so the
     checks still work. This is only for analysis - we never open anything. */
  function defang(text) {
    return String(text || '')
      .replace(/hxxps/gi, 'https')
      .replace(/hxxp/gi, 'http')
      .replace(/\[\.\]|\(\.\)|\{\.\}|\s?\[dot\]\s?|\[dot\]/gi, '.')
      .replace(/\[:\]/g, ':')
      .replace(/\[at\]/gi, '@')
      .replace(/\[@\]/g, '@')
      .replace(/\[\.]/g, '.');
  }

  /* Squash whitespace so evidence lines are tidy. */
  function tidy(value) {
    return String(value || '').replace(/\s+/g, ' ').trim();
  }

  /* Return a readable window of text around a match, so the user can see the
     sentence an indicator came from. */
  function excerptAround(text, index, length) {
    var start = Math.max(0, index - 70);
    var end = Math.min(text.length, index + length + 70);
    var snippet = tidy(text.slice(start, end));
    return (start > 0 ? '... ' : '') + snippet + (end < text.length ? ' ...' : '');
  }

  /* ------------------------------------------------------------------
     Parsing: email addresses and headers
     ------------------------------------------------------------------ */

  /* Turn "Microsoft 365 <alerts@example-mail.example>" into its parts.
     Returns { display, address, domain } or null. */
  function parseAddress(value) {
    if (!value) { return null; }
    var v = tidy(String(value)
      .replace(/^["']|["']$/g, '')
      .replace(/\([^)]*\)/g, ' '));          /* drop comment parts */
    v = v.replace(/^\s*(from|by|for|with)\s+mail\s+from\s*:?/i, ''); /* MAIL FROM: */
    var addr = null;
    var display = '';
    var angle = v.match(/<\s*([^>\s]+@[^>\s]+)\s*>/);
    if (angle) {
      addr = angle[1];
      display = v.slice(0, angle.index).trim();
    } else {
      var plain = v.match(/[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/);
      addr = plain ? plain[0] : null;
      display = plain ? v.replace(plain[0], '').trim() : v;
    }
    if (!addr) {
      return display ? { display: display, address: '', domain: '' } : null;
    }
    addr = addr.replace(/[>,;]+$/, '').trim();
    var domain = (addr.split('@').pop() || '').toLowerCase().replace(/[>,;.\s]+$/, '');
    return { display: tidy(display), address: addr, domain: domain };
  }

  /* Read pasted email headers. Headers are "Name: value" lines, and a value
     may continue on the following line if that line starts with a space. */
  function parseHeaders(rawText) {
    var text = String(rawText || '').replace(/\r\n?/g, '\n');
    var lines = text.split('\n');
    var map = {};
    var fieldCount = 0;
    var currentName = null;
    var foundKnown = 0;

    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      var m = line.match(/^([A-Za-z][A-Za-z0-9-]{1,38}):\s*(.*)$/);
      if (m) {
        currentName = m[1].toLowerCase();
        fieldCount++;
        if (HEADER_NAMES.indexOf(currentName) !== -1) { foundKnown++; }
        map[currentName] = map[currentName] ? map[currentName] + '\n' + m[2] : m[2];
      } else if (/^[ \t]+\S/.test(line) && currentName) {
        map[currentName] = map[currentName] + ' ' + line.trim();
      } else if (line.trim() === '') {
        currentName = null;
      } else {
        currentName = null;
      }
    }

    /* We only claim "headers were provided" when there is real evidence of a
       header block, so that ordinary sentences are never misread as headers. */
    var present = foundKnown >= 2 || (!!map['authentication-results']) || (!!map['received']);
    var auth = null;
    var receivedChain = [];

    if (present) {
      var authText = [
        map['authentication-results'] || '',
        map['arc-authentication-results'] || '',
        map['received-spf'] || ''
      ].join(' \n ').toLowerCase();

      auth = {
        spf: extractAuthResult(authText, 'spf', 'worst'),
        dkim: extractAuthResult(authText, 'dkim', 'best'),
        dmarc: extractAuthResult(authText, 'dmarc', 'worst'),
        raw: tidy(authText.replace(/\n/g, ' ')).slice(0, 400)
      };
      var received = (map['received'] || '').split('\n');
      for (var r = 0; r < received.length && r < 6; r++) {
        if (tidy(received[r])) { receivedChain.push(tidy(received[r]).slice(0, 220)); }
      }
    }

    return {
      present: present,
      fieldCount: fieldCount,
      fields: Object.keys(map),
      map: map,
      from: present ? parseAddress(map['from']) : null,
      replyTo: present ? parseAddress(map['reply-to']) : null,
      returnPath: present ? parseAddress(map['return-path'] || map['errors-to'] || map['sender']) : null,
      subject: present ? tidy(map['subject'] || '') : '',
      messageId: present ? tidy(map['message-id'] || '') : '',
      auth: auth,
      receivedChain: receivedChain
    };
  }

  /* Pull spf= / dkim= / dmarc= results out of the authentication headers.
     "worst" keeps the most alarming result (used for SPF and DMARC, where one
     failure is a failure); "best" prefers a pass (used for DKIM, because a
     message may carry several signatures and only one needs to be valid). */
  var AUTH_ORDER = ['fail', 'permerror', 'softfail', 'temperror', 'neutral',
    'none', 'policy', 'pass'];
  function extractAuthResult(text, name, mode) {
    var re = new RegExp('\\b' + name + '\\s*=\\s*([a-z]+)', 'g');
    var found = null;
    var m;
    while ((m = re.exec(text)) !== null) {
      var value = m[1];
      if (value === 'unknown') { continue; }
      if (found === null) { found = value; continue; }
      var oldRank = AUTH_ORDER.indexOf(found);
      var newRank = AUTH_ORDER.indexOf(value);
      if (oldRank === -1) { oldRank = AUTH_ORDER.length; }
      if (newRank === -1) { newRank = AUTH_ORDER.length; }
      if (mode === 'worst' && newRank < oldRank) { found = value; }
      if (mode === 'best' && newRank > oldRank) { found = value; }
    }
    if (found === 'softfail' && mode === 'best') { found = 'softfail'; }
    return found;
  }

  /* ------------------------------------------------------------------
     Parsing: links, link text and attachment names
     ------------------------------------------------------------------ */

  /* One shared recipe for "what a link looks like", so every check agrees. */
  var URL_RE_SOURCE = '\\b(?:https?|ftp):\\/\\/[^\\s<>"\'`()\\[\\]{}]+'
    + '|\\bwww\\.[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)+(?:\\/[^\\s<>"\'`()\\[\\]{}]*)?';
  var EMAIL_RE_SOURCE = '[A-Za-z0-9._%+\'-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}';

  function findUrls(text) {
    var re = new RegExp(URL_RE_SOURCE, 'gi');
    var out = [];
    var m;
    while ((m = re.exec(String(text || ''))) !== null) {
      var raw = m[0].replace(/[.,;:!?"')\]}]+$/, '');   /* trailing punctuation */
      if (!raw) { continue; }
      out.push(/^www\./i.test(raw) ? 'http://' + raw : raw);
    }
    return out;
  }

  /* Break a link into the parts the rules need in order to judge it. */
  function parseUrl(href) {
    var raw = String(href || '').trim();
    var schemeMatch = raw.match(/^([a-z][a-z0-9+.-]*):\/\//i);
    var scheme = schemeMatch ? schemeMatch[1].toLowerCase() : 'http';
    var rest = raw.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
    var authority = rest.split(/[\/?#]/)[0];
    var remainder = rest.slice(authority.length);
    var hasUserInfo = authority.indexOf('@') !== -1;
    var hostPort = hasUserInfo ? authority.split('@').pop() : authority;
    var port = null;
    var host = hostPort;

    if (/^\[/.test(hostPort)) {                       /* IPv6 in brackets */
      var bracket = hostPort.match(/^\[([^\]]+)\](?::(\d+))?/);
      if (bracket) {
        host = bracket[1];
        port = bracket[2] || null;
      }
    } else if (/:\d+$/.test(hostPort)) {
      port = hostPort.split(':').pop();
      host = hostPort.replace(/:\d+$/, '');
    }

    host = host.toLowerCase().replace(/\.+$/, '');
    var pathPart = remainder.split('?')[0] || '';
    var query = remainder.indexOf('?') !== -1 ? remainder.slice(remainder.indexOf('?') + 1) : '';
    var isIp = HELPERS.isIpHost(host);

    return {
      href: raw,
      scheme: scheme,
      host: host,
      registrable: isIp ? host : HELPERS.registrableDomain(host),
      path: pathPart,
      query: query,
      port: port,
      hasUserInfo: hasUserInfo,
      isIp: isIp
    };
  }

  function extractUrls(text) {
    var raw = findUrls(text);
    var seen = {};
    var urls = [];
    for (var i = 0; i < raw.length; i++) {
      var key = raw[i].toLowerCase();
      if (seen[key]) { continue; }
      seen[key] = true;
      urls.push(parseUrl(raw[i]));
    }
    return urls;
  }

  /* Is this word a domain name we should take seriously? Requiring a
     recognisable domain ending stops "john.smith" being read as a domain. */
  function isDomainToken(token) {
    var labels = HELPERS.labelsOf(token);
    if (labels.length < 2) { return false; }
    if (labels[labels.length - 1].length < 2) { return false; }
    return KNOWN_TLDS.indexOf(labels[labels.length - 1]) !== -1;
  }

  /* Collect pairs of "what the link says" and "where it really goes".
     Two sources: real HTML links, and plain text such as
     "Sign in at login.example.com (https://totally-different.example/login)". */
  function extractAnchors(text, defangedText) {
    var anchors = [];
    var htmlRe = /<a\b[^>]*href\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>([\s\S]*?)<\/a>/gi;
    var m;
    while ((m = htmlRe.exec(String(text || ''))) !== null) {
      var href = tidy(m[1] || m[2] || m[3] || '');
      var label = tidy(stripTags(m[4] || ''));
      if (href) { anchors.push({ text: label, href: href, kind: 'html' }); }
    }

    /* Plain-text pattern: a domain-looking word on the same line as a link. */
    var lines = String(defangedText || '').split('\n');
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      var lineUrls = findUrls(line);
      if (!lineUrls.length) { continue; }
      var withoutUrls = line.replace(new RegExp(URL_RE_SOURCE, 'gi'), ' ')
        .replace(new RegExp(EMAIL_RE_SOURCE, 'g'), ' ');
      var tokens = withoutUrls.match(/\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b/g) || [];
      for (var t = 0; t < tokens.length; t++) {
        if (!isDomainToken(tokens[t])) { continue; }
        anchors.push({ text: tokens[t], href: lineUrls[0], kind: 'text' });
        break;   /* one pair per line is enough */
      }
    }
    return anchors;
  }

  function escapeRegExp(value) {
    return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  /* Attachment names are usually mentioned inside a sentence ("see the
     attached Remittance_Advice.docm"). This trims the lead-in words so the
     evidence shown to the user is just the filename itself. */
  var LEAD_IN_WORDS = ['please', 'see', 'find', 'open', 'review', 'sign', 'check',
    'download', 'view', 'attached', 'attachment', 'copy', 'of', 'the', 'a', 'an',
    'our', 'your', 'my', 'this', 'that', 'new', 'updated', 'here', 'is', 'are',
    'and', 'to', 'from', 'file', 'document', 'in', 'it', 'we', 'have', 'has', 'i'];

  function trimFilenamePrefix(prefix) {
    var n = String(prefix || '').trim();

    /* Anything before a ". " belonged to the previous sentence, not the name. */
    var lastDotSpace = n.lastIndexOf('. ');
    if (lastDotSpace !== -1) { n = n.slice(lastDotSpace + 2).trim(); }

    var changed = true;
    while (changed) {
      changed = false;
      var m = n.match(/^([A-Za-z]+)[ \t]+/);
      if (m && LEAD_IN_WORDS.indexOf(m[1].toLowerCase()) !== -1 && n.length - m[0].length >= 4) {
        n = n.slice(m[0].length).trim();
        changed = true;
      }
    }
    return n;
  }

  /* Find attachment filenames mentioned anywhere in the message. Links and
     email addresses are blanked out first, so "example.com" is never mistaken
     for a file called "example.com". */
  function extractAttachments(text) {
    var scan = String(text || '')
      .replace(new RegExp(URL_RE_SOURCE, 'gi'), ' ')
      .replace(new RegExp(EMAIL_RE_SOURCE, 'g'), ' ');

    var extAlt = ALL_ATTACHMENT_EXTS.map(escapeRegExp).join('|');
    var re = new RegExp('([A-Za-z0-9][A-Za-z0-9 _\\-\\.]{0,70}?)\\.(' + extAlt + ')(?![A-Za-z0-9])', 'gi');
    var seen = {};
    var attachments = [];
    var m;

    while ((m = re.exec(scan)) !== null) {
      var name = tidy(trimFilenamePrefix(m[1]) + '.' + m[2]);
      var ext = m[2].toLowerCase();
      if (!name || name.length < 4) { continue; }
      if (!/^[A-Za-z0-9]/.test(name)) { continue; }
      if (seen[name.toLowerCase()]) { continue; }

      var parts = name.split('.');
      var decoy = parts.length >= 3 ? parts[parts.length - 2].toLowerCase() : null;
      var isDouble = !!decoy && DATA.decoyExts.indexOf(decoy) !== -1;
      var allLabelsSimple = parts.every(function (p) { return /^[A-Za-z0-9-]+$/.test(p); });
      var looksLikeDomain = allLabelsSimple && KNOWN_TLDS.indexOf(ext) !== -1;

      /* "sub.example.com" is a domain name, not a file - unless it hides a
         decoy extension, as in "invoice.pdf.com". */
      if (looksLikeDomain && !isDouble) { continue; }

      seen[name.toLowerCase()] = true;

      var odd = [];
      if (name.length >= 45) { odd.push('very long filename'); }
      if (/[^\x20-\x7E]/.test(name)) { odd.push('contains non-English characters'); }
      if (parts.length >= 4) { odd.push('unusually many dots'); }
      if (/[A-Fa-f0-9]{12,}/.test(name.replace(/\./g, ''))) { odd.push('random-looking block of characters'); }
      if (/(^|\s)(scan|img|doc|file|photo|copy|new)\d{3,}/i.test(name)) { odd.push('scanner-style auto-generated name'); }

      attachments.push({
        name: name,
        ext: ext,
        isDoubleExtension: isDouble,
        decoyExt: isDouble ? decoy : null,
        looksOdd: odd.length > 0,
        oddReason: odd.length ? odd.join(', ') : ''
      });
    }
    return attachments;
  }

  /* ------------------------------------------------------------------
     Build the context object that the rules are given
     ------------------------------------------------------------------ */
  function buildContext(rawText) {
    var text = String(rawText || '').replace(/\r\n?/g, '\n');
    var defanged = defang(text);
    var visible = stripTags(defanged);

    return {
      text: text,
      lower: visible.toLowerCase(),
      visible: visible,
      urls: extractUrls(defanged),
      anchors: extractAnchors(text, defanged),
      attachments: extractAttachments(text),
      headerInfo: parseHeaders(text),
      helpers: HELPERS
    };
  }

  /* ------------------------------------------------------------------
     Running the rules
     ------------------------------------------------------------------ */

  /* Build a RegExp from a rule pattern.
     - "forceInsensitive" makes text checks case-insensitive, because attackers
       happily write in CAPITALS to be noticed.
     - Guard patterns (the "unless" lists) are left case-sensitive when they
       deliberately contain capitals, e.g. /\bdear [A-Z][a-z]+ [A-Z][a-z]+\b/
       which checks whether a real person's name follows "Dear". */
  function buildRegex(pattern, forceInsensitive) {
    var flags = pattern.flags || '';
    if (flags.indexOf('g') === -1) { flags += 'g'; }
    if (forceInsensitive && flags.indexOf('i') === -1) { flags += 'i'; }
    return new RegExp(pattern.source, flags);
  }

  function guardMatches(pattern, text) {
    return buildRegex(pattern, !/[A-Z]/.test(pattern.source)).test(text);
  }

  /* Run one text-based rule against the visible message text. */
  function runPhraseRule(rule, ctx) {
    var text = ctx.visible;

    if (rule.unless) {
      for (var u = 0; u < rule.unless.length; u++) {
        if (guardMatches(rule.unless[u], text)) { return null; }
      }
    }

    var matches = [];
    var matchCount = 0;
    var firstIndex = -1;
    var firstLength = 0;

    for (var i = 0; i < rule.patterns.length; i++) {
      var re = buildRegex(rule.patterns[i], true);
      var m;
      var safety = 0;
      while ((m = re.exec(text)) !== null) {
        if (m[0] === '') { re.lastIndex++; continue; }
        matchCount++;
        var clean = tidy(m[0]);
        if (clean && matches.indexOf(clean) === -1 && matches.length < 4) { matches.push(clean); }
        if (firstIndex === -1) { firstIndex = m.index; firstLength = m[0].length; }
        if (++safety > 200) { break; }
      }
    }

    if (!matchCount) { return null; }

    return {
      matchCount: matchCount,
      matches: matches,
      excerpt: excerptAround(text, firstIndex, firstLength)
    };
  }

  /* Run one logic-based rule. A broken rule is skipped rather than allowed to
     break the whole analysis (the warning goes to the browser console only). */
  function runCustomRule(rule, ctx) {
    try {
      var out = rule.test(ctx);
      if (!out) { return null; }
      return { evidence: out.evidence || '', note: out.note || '', matches: [], matchCount: 1 };
    } catch (err) {
      if (typeof console !== 'undefined' && console.warn) {
        console.warn('Rule "' + rule.id + '" could not run:', err && err.message);
      }
      return null;
    }
  }

  /* ------------------------------------------------------------------
     Scoring: add the points, apply the per-category caps, cap at 100
     ------------------------------------------------------------------ */
  function scoreFindings(findings) {
    var perCategory = {};
    var totalRaw = 0;

    findings.forEach(function (f) {
      if (f.informational) { return; }
      totalRaw += f.weight;
      var cat = perCategory[f.category];
      if (!cat) {
        var meta = rules.CATEGORIES[f.category] || { label: f.category, cap: 100, blurb: '' };
        cat = perCategory[f.category] = {
          id: f.category,
          label: meta.label,
          blurb: meta.blurb,
          cap: meta.cap,
          raw: 0,
          applied: 0,
          capped: false
        };
      }
      cat.raw += f.weight;
    });

    var categories = [];
    var total = 0;
    /* Keep the categories in the order they are declared in rules.js. */
    Object.keys(rules.CATEGORIES).forEach(function (id) {
      if (!perCategory[id]) { return; }
      var cat = perCategory[id];
      cat.applied = Math.min(cat.raw, cat.cap);
      cat.capped = cat.raw > cat.cap;
      cat.percentOfCap = cat.cap ? Math.round((cat.applied / cat.cap) * 100) : 0;
      total += cat.applied;
      categories.push(cat);
    });

    return {
      categories: categories,
      totalRaw: totalRaw,
      cappedTotal: total,
      score: Math.max(0, Math.min(100, total)),
      hitCategoryCap: categories.some(function (c) { return c.capped; }),
      hitOverallCap: total > 100
    };
  }

  /* ------------------------------------------------------------------
     Informational notes (never scored - they teach rather than accuse)
     ------------------------------------------------------------------ */
  function buildNotes(ctx, findings, scoreInfo) {
    var notes = [];
    var info = ctx.headerInfo;
    var visible = ctx.visible || '';

    if (!info.present) {
      notes.push({
        tone: 'warn',
        title: 'Full email headers were not detected',
        text: 'SPF, DKIM and DMARC checks and the Reply-To comparison can only run if you paste the email\'s full headers. In most mail programs these are behind an option such as "Show original", "View source" or "Show message headers".'
      });
    } else {
      var auth = info.auth || {};
      var passed = [];
      var failed = [];
      ['spf', 'dkim', 'dmarc'].forEach(function (name) {
        if (auth[name] === 'pass') { passed.push(name.toUpperCase()); }
        if (auth[name] === 'fail' || auth[name] === 'softfail') { failed.push(name.toUpperCase()); }
      });
      if (passed.length) {
        notes.push({
          tone: 'good',
          title: 'Authentication checks that passed: ' + passed.join(', '),
          text: 'Passing checks make forgery harder, but they are not proof of good intent - a fraudster can send from a domain they legitimately own that passes every check.'
        });
      }
      if (failed.length) {
        notes.push({
          tone: 'warn',
          title: 'Authentication checks that failed: ' + failed.join(', '),
          text: 'See the individual findings below for what each of these means.'
        });
      }
      if (info.fields.length) {
        notes.push({
          tone: 'info',
          title: info.fields.length + ' header field(s) were read',
          text: 'Headers detected: ' + info.fields.slice(0, 12).join(', ') + (info.fields.length > 12 ? '...' : '')
        });
      }
    }

    notes.push({
      tone: 'info',
      title: 'What was examined',
      text: visible.length + ' characters, ' + ctx.urls.length + ' link(s), '
        + ctx.anchors.length + ' link-text pair(s), ' + ctx.attachments.length
        + ' attachment name(s) found in the pasted text.'
    });

    if (!ctx.urls.length) {
      notes.push({
        tone: 'good',
        title: 'No links were found in the message',
        text: 'That removes one of the most common phishing mechanisms - but a message can still try to talk you into replying with information.'
      });
    }
    if (!ctx.attachments.length) {
      notes.push({
        tone: 'info',
        title: 'No attachment filenames were found',
        text: 'If the email really had an attachment, its name may simply not appear in the text you pasted. Check for yourself before opening anything.'
      });
    }
    if (tidy(visible).length < 40) {
      notes.push({
        tone: 'warn',
        title: 'Very little text was analysed',
        text: 'With so little to go on, a low score means very little. Paste the whole message for a useful result.'
      });
    }
    if (scoreInfo.hitCategoryCap) {
      notes.push({
        tone: 'info',
        title: 'A category cap was applied',
        text: 'One category produced more points than it is allowed to contribute. Caps stop a single repetitive trick from inflating the score.'
      });
    }
    return notes;
  }

  /* ------------------------------------------------------------------
     Recommendations - practical next steps
     ------------------------------------------------------------------ */
  function buildRecommendations(ctx, findings, band) {
    var issues = {};
    findings.forEach(function (f) { issues[f.category] = true; });
    var recs = [];

    if (issues.links || ctx.urls.length) {
      recs.push({
        title: 'Do not click any link in this message',
        text: 'Links can lead to convincing copies of real sign-in pages. If you need to reach the organisation, type its address into your browser or use its official app.'
      });
    }
    if (issues.credentials) {
      recs.push({
        title: 'Treat any password or code you may have entered as compromised',
        text: 'Change the password through the service\'s own website or app, make it unique, and turn on multi-factor authentication. If you shared a one-time code, sign out of all active sessions.'
      });
    }
    if (issues.payment || issues.bec) {
      recs.push({
        title: 'Confirm any payment request by telephone before acting',
        text: 'Phone the person or supplier using a number from your own records or their official website - never a number given in the message. Banks and tax authorities never ask for gift cards.'
      });
    }
    if (issues.attachments) {
      recs.push({
        title: 'Do not open the attachment or enable macros',
        text: 'Attachments can install software. If the sender looks like somebody you know, contact them another way and ask - their account may already be compromised.'
      });
    }
    if (band.id !== 'low') {
      recs.push({
        title: 'Verify the message through an independent channel',
        text: 'Log in to the organisation\'s official website or app, or call a number you already have. Do not use any contact details from the message itself. Doing nothing is a fine answer: no harm comes from simply ignoring a phishing email.'
      });
      recs.push({
        title: 'Report it, then delete it',
        text: 'Forward it to your IT or security team, or to a national anti-phishing service (for example reportfraud.ftc.gov, actionfraud.police.uk, or report@phishing.gov.uk in the UK). Reporting protects other people too.'
      });
    } else {
      recs.push({
        title: 'Stay normally cautious',
        text: 'A low score is not a clean bill of health. If the message was unexpected, or asks for money, credentials or a change of bank details, verify it independently before acting.'
      });
      recs.push({
        title: 'Check anything you were not expecting',
        text: 'Contact the sender using details you already have. If an invoice or payment is involved, match it against records you already hold.'
      });
    }

    if (!ctx.headerInfo.present) {
      recs.push({
        title: 'Paste the full headers for a stronger result',
        text: 'Use "Show original" or "View source" in your mail program. The technical headers let the analyser check SPF, DKIM, DMARC and the Reply-To address, which is where forged messages often give themselves away.'
      });
    }
    return recs;
  }

  function buildSummary(findings, scoreInfo) {
    if (!findings.length) {
      return 'No warning signs from the checklist were found in this message.';
    }
    var strongest = findings.slice(0, 3).map(function (f) { return f.title.toLowerCase(); });
    return findings.length + ' warning sign' + (findings.length === 1 ? '' : 's')
      + ' detected. The most significant: ' + strongest.join('; ')
      + '. Combined category points: ' + scoreInfo.cappedTotal
      + (scoreInfo.hitOverallCap ? ' (capped at 100)' : '') + '.';
  }

  /* Turn a triggered rule into the finding object the interface displays. */
  function makeFinding(rule, out, isCustom) {
    var meta = rules.CATEGORIES[rule.category] || { label: rule.category, cap: 100 };
    return {
      id: rule.id,
      category: rule.category,
      categoryLabel: meta.label,
      categoryCap: meta.cap,
      title: rule.title,
      weight: rule.weight,
      why: rule.why,
      tip: rule.tip || '',
      evidence: isCustom ? out.evidence : out.excerpt,
      matches: out.matches || [],
      matchCount: out.matchCount || 1,
      note: out.note || '',
      informational: !!rule.informational
    };
  }

  /* ------------------------------------------------------------------
     The main entry point
     ------------------------------------------------------------------ */
  function analyse(rawText) {
    var text = rawText == null ? '' : String(rawText);
    var empty = tidy(stripTags(defang(text))).length === 0;

    if (empty) {
      return {
        ok: false,
        reason: 'empty',
        message: 'Paste the text of an email (and its headers, if you have them) before analysing.'
      };
    }

    var ctx = buildContext(text);
    var findings = [];

    rules.PHRASE_RULES.forEach(function (rule) {
      var out = runPhraseRule(rule, ctx);
      if (out) { findings.push(makeFinding(rule, out, false)); }
    });

    rules.CUSTOM_RULES.forEach(function (rule) {
      var out = runCustomRule(rule, ctx);
      if (out) { findings.push(makeFinding(rule, out, true)); }
    });

    /* Strongest signals first, so the most important explanation is at the top. */
    findings.sort(function (a, b) {
      if (b.weight !== a.weight) { return b.weight - a.weight; }
      return a.title.localeCompare(b.title);
    });

    var scoreInfo = scoreFindings(findings);
    var band = rules.bandFor(scoreInfo.score);

    return {
      ok: true,
      score: scoreInfo.score,
      scoreBeforeCaps: scoreInfo.totalRaw,
      band: band,
      summary: buildSummary(findings, scoreInfo),
      findings: findings,
      categories: scoreInfo.categories,
      hitCategoryCap: scoreInfo.hitCategoryCap,
      hitOverallCap: scoreInfo.hitOverallCap,
      notes: buildNotes(ctx, findings, scoreInfo),
      recommendations: buildRecommendations(ctx, findings, band),
      headers: ctx.headerInfo,
      stats: {
        characters: text.length,
        words: (tidy(ctx.visible).match(/\S+/g) || []).length,
        links: ctx.urls.length,
        attachments: ctx.attachments.length,
        headerFields: ctx.headerInfo.fieldCount,
        urls: ctx.urls.map(function (u) { return { href: u.href, host: u.host, registrable: u.registrable }; }),
        attachmentNames: ctx.attachments.map(function (a) { return a.name; })
      },
      /* Shown with every result, whatever the score. */
      disclaimer: 'This is an educational triage tool. It identifies warning signs by '
        + 'matching the text against known phishing patterns - it cannot prove that an '
        + 'email is malicious, and a low score cannot prove that an email is safe. '
        + 'Never click a link or open an attachment just to see what happens.'
    };
  }

  return {
    analyse: analyse,
    /* Exported for the developer test script and for future features. */
    buildContext: buildContext,
    parseHeaders: parseHeaders,
    parseAddress: parseAddress,
    extractUrls: extractUrls,
    extractAnchors: extractAnchors,
    extractAttachments: extractAttachments,
    parseUrl: parseUrl,
    scoreFindings: scoreFindings,
    stripTags: stripTags,
    defang: defang,
    KNOWN_TLDS: KNOWN_TLDS
  };
});