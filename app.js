/* ==========================================================================
   Phishing Email Analyser - js/app.js
   --------------------------------------------------------------------------
   The interface layer: it wires the button and the tabs to the analyser and
   draws the results. All of the thinking happens in analyzer.js and rules.js.

   Two habits worth noticing, because both are standard security practice:
     1. We never use innerHTML with anything that came from the pasted email.
        Everything is built with document.createElement + textContent, so a
        malicious "email" cannot inject code into this page.
     2. We never store the email anywhere: no cookies, no localStorage, no
        browsing-history entry. It lives in memory until you clear it or close
        the tab.
   ========================================================================== */
(function () {
  'use strict';

  var rules = window.PEA.rules;
  var analyzer = window.PEA.analyzer;
  var demos = window.PEA.demos.demos;

  /* ---------- tiny DOM helpers ---------- */
  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) { node.className = className; }
    if (text !== undefined && text !== null) { node.textContent = String(text); }
    return node;
  }
  function clear(node) { while (node.firstChild) { node.removeChild(node.firstChild); } }
  function $(id) { return document.getElementById(id); }

  /* ---------- element references ---------- */
  var ui = {
    textarea: $('email-input'),
    charCount: $('char-count'),
    analyseBtn: $('analyse-btn'),
    clearBtn: $('clear-btn'),
    copyBtn: $('copy-btn'),
    demoSelect: $('demo-select'),
    demoNote: $('demo-note'),
    resetDemosBtn: $('reset-demos-btn'),
    results: $('results'),
    verdictCard: $('verdict-card'),
    gaugeFill: $('gauge-fill'),
    gaugeScore: $('gauge-score'),
    bandMarker: $('band-marker'),
    verdictTitle: $('verdict-title'),
    verdictSummary: $('verdict-summary'),
    verdictFacts: $('verdict-facts'),
    disclaimer: $('disclaimer'),
    panelFindings: $('panel-findings'),
    panelNext: $('panel-next'),
    panelHeaders: $('panel-headers'),
    panelScoring: $('panel-scoring'),
    panelPrivacy: $('panel-privacy'),
    tabs: Array.prototype.slice.call(document.querySelectorAll('.tab'))
  };

  var state = { lastResult: null, activeDemoId: null, activeDemoName: '' };
  var demoCallout = null;   /* the "this demo is designed to score..." note */
  var GAUGE_CIRCUMFERENCE = 2 * Math.PI * 58;

  /* A small status line under the buttons, for messages like "nothing to read". */
  var status = el('p', 'hint');
  status.setAttribute('role', 'status');
  ui.analyseBtn.parentNode.parentNode.insertBefore(status, ui.analyseBtn.parentNode.nextSibling);

  /* ==========================================================
     Tabs
     ========================================================== */
  function panelFor(tab) { return $(tab.getAttribute('aria-controls')); }

  function selectTab(tab, moveFocus) {
    ui.tabs.forEach(function (other) {
      var isActive = other === tab;
      other.setAttribute('aria-selected', isActive ? 'true' : 'false');
      other.tabIndex = isActive ? 0 : -1;
      panelFor(other).hidden = !isActive;
    });
    if (moveFocus) { tab.focus(); }
  }

  ui.tabs.forEach(function (tab) {
    tab.addEventListener('click', function () { selectTab(tab); });
    tab.addEventListener('keydown', function (event) {
      var index = ui.tabs.indexOf(tab);
      var next = null;
      if (event.key === 'ArrowRight') { next = ui.tabs[(index + 1) % ui.tabs.length]; }
      if (event.key === 'ArrowLeft') { next = ui.tabs[(index - 1 + ui.tabs.length) % ui.tabs.length]; }
      if (event.key === 'Home') { next = ui.tabs[0]; }
      if (event.key === 'End') { next = ui.tabs[ui.tabs.length - 1]; }
      if (next) { event.preventDefault(); selectTab(next, true); }
    });
  });

  /* ==========================================================
     Demo emails
     ========================================================== */
  demos.forEach(function (demo) {
    var option = el('option', null, demo.name);
    option.value = demo.id;
    ui.demoSelect.appendChild(option);
  });

  ui.demoSelect.addEventListener('change', function () {
    var demo = demos.filter(function (d) { return d.id === ui.demoSelect.value; })[0];
    if (!demo) {
      ui.demoNote.hidden = true;
      ui.resetDemosBtn.hidden = true;
      state.activeDemoId = null;
      return;
    }
    ui.textarea.value = demo.text;
    updateCharCount();
    state.activeDemoId = demo.id;
    state.activeDemoName = demo.name;
    ui.resetDemosBtn.hidden = false;
    clear(ui.demoNote);
    ui.demoNote.appendChild(el('strong', null, demo.name + ' - ' + demo.tagline));
    ui.demoNote.appendChild(el('span', null, ' ' + demo.whatToNotice));
    ui.demoNote.hidden = false;
    status.textContent = 'Demo loaded. Everything in it is fictional - press Analyse Email.';
  });

  ui.resetDemosBtn.addEventListener('click', function () {
    ui.textarea.value = '';
    ui.demoSelect.value = '';
    ui.demoNote.hidden = true;
    ui.resetDemosBtn.hidden = true;
    state.activeDemoId = null;
    ui.results.hidden = true;
    status.textContent = '';
    updateCharCount();
    ui.textarea.focus();
  });

  /* ==========================================================
     Input handling
     ========================================================== */
  function updateCharCount() {
    var count = ui.textarea.value.length;
    ui.charCount.textContent = count.toLocaleString() + (count === 1 ? ' character' : ' characters');
  }

  ui.textarea.addEventListener('input', function () {
    updateCharCount();
    if (status.textContent) { status.textContent = ''; }
    if (state.activeDemoId) {
      var demo = demos.filter(function (d) { return d.id === state.activeDemoId; })[0];
      if (demo && ui.textarea.value !== demo.text) {
        /* The text has been edited away from the demo - stop calling it a demo. */
        state.activeDemoId = null;
        state.activeDemoName = '';
      }
    }
  });

  ui.clearBtn.addEventListener('click', function () {
    ui.textarea.value = '';
    ui.results.hidden = true;
    ui.copyBtn.hidden = true;
    ui.demoSelect.value = '';
    ui.demoNote.hidden = true;
    ui.resetDemosBtn.hidden = true;
    state.lastResult = null;
    state.activeDemoId = null;
    status.textContent = '';
    updateCharCount();
    ui.textarea.focus();
  });

  ui.textarea.addEventListener('keydown', function (event) {
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
      event.preventDefault();
      runAnalysis();
    }
  });

  ui.analyseBtn.addEventListener('click', runAnalysis);

  function runAnalysis() {
    status.textContent = '';
    var text = ui.textarea.value;

    if (!text.trim()) {
      status.textContent = 'Paste the text of an email first - or load one of the demo emails above.';
      ui.textarea.focus();
      return;
    }

    /* The only call that does any work, and it stays inside this browser tab. */
    var result = analyzer.analyse(text);

    if (!result.ok) {
      status.textContent = result.message;
      return;
    }

    state.lastResult = result;
    renderResult(result);
    ui.results.hidden = false;
    ui.copyBtn.hidden = false;
    selectTab(ui.tabs[0]);

    var reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    window.scrollTo({ top: ui.results.offsetTop - 70, behavior: reduceMotion ? 'auto' : 'smooth' });
  }

  /* ==========================================================
     Rendering: the verdict
     ========================================================== */
  function renderResult(result) {
    var band = result.band;

    ui.verdictCard.className = 'card verdict-card band-' + band.id;

    ui.gaugeScore.textContent = String(result.score);
    var offset = GAUGE_CIRCUMFERENCE * (1 - result.score / 100);
    ui.gaugeFill.style.strokeDashoffset = String(GAUGE_CIRCUMFERENCE);
    window.requestAnimationFrame(function () {
      ui.gaugeFill.style.strokeDashoffset = String(offset);
    });
    /* The marker is clamped slightly inside the bar so that, at a score of 100,
       it stays visible instead of being pushed off the right-hand edge. */
    ui.bandMarker.style.left = Math.max(0, Math.min(99, result.score)) + '%';

    clear(ui.verdictTitle);
    ui.verdictTitle.appendChild(el('span', 'verdict-icon', band.icon));
    ui.verdictTitle.appendChild(el('span', null, band.label));

    ui.verdictSummary.textContent = band.summary;

    /* The honest, auditable arithmetic - not a mysterious number. */
    clear(ui.verdictFacts);
    function fact(value, label) {
      var li = el('li');
      li.appendChild(el('strong', null, value + ' '));
      li.appendChild(document.createTextNode(label));
      ui.verdictFacts.appendChild(li);
    }
    fact(String(result.findings.length), 'warning signs found');
    fact(String(result.categories.length), 'categories involved');
    fact(String(result.scoreBeforeCaps), 'points before caps');
    if (result.scoreBeforeCaps !== result.score) {
      fact(String(result.score), 'after caps and the 100-point ceiling');
    }
    fact(String(result.stats.links), 'links found');
    fact(String(result.stats.attachments), 'attachment names found');
    fact(result.headers.present ? 'detected' : 'not detected', 'headers');

    /* Did this demo behave as designed? Useful when you are learning. */
    if (demoCallout && demoCallout.parentNode) {
      demoCallout.parentNode.removeChild(demoCallout);
      demoCallout = null;
    }
    if (state.activeDemoId) {
      var demo = demos.filter(function (d) { return d.id === state.activeDemoId; })[0];
      if (demo) {
        var label = bandLabel(demo.expectedBand);
        var matches = demo.expectedBand === band.id;
        var note = el('p', 'callout');
        note.appendChild(el('strong', null, matches
          ? 'This demo is designed to score ' + label + ' - your result matches.'
          : 'This demo is designed to score ' + label + ', and this analysis came out ' + band.label + '.'));
        note.appendChild(el('span', null, matches
          ? ' The demo emails are completely fictional, so you can explore the warning signs safely.'
          : ' Worth investigating: every rule and its points are listed in the "How scoring works" tab.'));
        demoCallout = note;
        ui.disclaimer.parentNode.insertBefore(note, ui.disclaimer);
      }
    }

    ui.disclaimer.textContent = result.disclaimer;
    renderFindings(result);
    renderRecommendations(result);
    renderHeaders(result);
  }

  function bandLabel(id) {
    var found = rules.BANDS.filter(function (b) { return b.id === id; })[0];
    return found ? found.label : id;
  }

  /* ==========================================================
     Rendering: the findings list
     ========================================================== */
  function renderFindings(result) {
    var panel = ui.panelFindings;
    clear(panel);

    var totalRules = rules.allRules().length;
    var intro = el('p', 'panel-intro');
    intro.textContent = result.findings.length
      ? result.findings.length + ' of the ' + totalRules + ' checks matched warning signs. They added up to '
        + result.scoreBeforeCaps + ' points before caps, reduced to ' + result.score
        + ' after the category caps and the 100-point ceiling. Each item below explains what was found, why it matters, and what it cost.'
      : 'None of the ' + totalRules + ' checks matched a warning sign in this message. That is a good sign, but it is not proof that the email is genuine - see the notes below.';
    panel.appendChild(intro);

    if (!result.findings.length) {
      var clean = el('div', 'callout');
      clean.appendChild(el('strong', null, 'No warning signs matched.'));
      clean.appendChild(el('p', null, 'Before you trust the message, ask three questions: was I expecting it, '
        + 'does it ask me to click, pay or log in, and does the sender address match the organisation it claims to be from? '
        + 'If any answer worries you, verify the message independently.'));
      panel.appendChild(clean);
    }

    /* Group the findings by category, in the order rules.js declares them. */
    result.categories.forEach(function (category) {
      var groupFindings = result.findings.filter(function (f) { return f.category === category.id; });
      if (!groupFindings.length) { return; }

      var group = el('div', 'finding-group');
      var head = el('div', 'finding-group-head');
      head.appendChild(el('h3', null, category.label));
      if (category.blurb) { head.appendChild(el('p', 'group-blurb', category.blurb)); }

      var capChip = el('span', 'group-cap' + (category.capped ? ' capped' : ''),
        category.applied + ' / ' + category.cap + ' points' + (category.capped ? ' (capped)' : ''));
      capChip.title = category.capped
        ? 'These checks found ' + category.raw + ' points, but this category may contribute at most '
          + category.cap + '. The cap stops one repeated trick from inflating the score.'
        : 'This category can contribute at most ' + category.cap + ' points.';
      head.appendChild(capChip);
      group.appendChild(head);

      groupFindings.forEach(function (finding) { group.appendChild(findingCard(finding)); });
      panel.appendChild(group);
    });

    /* Informational notes: never scored - they exist to teach. */
    if (result.notes.length) {
      panel.appendChild(el('h3', 'subhead', 'Notes about this analysis'));
      var notes = el('div', 'notes');
      result.notes.forEach(function (note) {
        var box = el('div', 'note note-' + note.tone);
        box.appendChild(el('span', 'note-icon',
          note.tone === 'good' ? '\u2714' : (note.tone === 'warn' ? '\u26A0' : '\u2139')));
        var body = el('div');
        body.appendChild(el('strong', null, note.title));
        body.appendChild(el('span', null, note.text));
        box.appendChild(body);
        notes.appendChild(box);
      });
      panel.appendChild(notes);
    }
  }

  function findingCard(finding) {
    var card = el('div', 'finding w-' + finding.weight);

    var head = el('div', 'finding-head');
    head.appendChild(el('h4', null, finding.title));
    head.appendChild(el('span', 'points',
      '+' + finding.weight + (finding.weight === 1 ? ' point' : ' points')));
    card.appendChild(head);

    card.appendChild(el('p', null, finding.why));

    if (finding.evidence) {
      var evidence = el('div', 'evidence');
      evidence.appendChild(el('span', 'evidence-label', 'What triggered it'));
      evidence.appendChild(document.createTextNode(finding.evidence));
      card.appendChild(evidence);
    }

    if (finding.matches && finding.matches.length) {
      var chips = el('ul', 'match-chips');
      chips.title = 'The exact text that matched';
      finding.matches.forEach(function (match) { chips.appendChild(el('li', null, match)); });
      card.appendChild(chips);
      if (finding.matchCount > finding.matches.length) {
        card.appendChild(el('p', 'caption', 'Matched ' + finding.matchCount + ' times in total.'));
      }
    }

    if (finding.note) { card.appendChild(el('p', 'caption', finding.note)); }
    if (finding.tip) { card.appendChild(el('p', 'tip', finding.tip)); }

    card.appendChild(el('p', 'caption', 'Rule id: ' + finding.id
      + ' | category cap: ' + finding.categoryCap + ' points.'));

    return card;
  }

  /* ==========================================================
     Rendering: what to do next
     ========================================================== */
  function renderRecommendations(result) {
    var panel = ui.panelNext;
    clear(panel);

    panel.appendChild(el('p', 'panel-intro',
      'Suggested next steps for this result, most important first. These are general good habits, '
      + 'not instructions specific to any one email.'));

    var list = el('ol', 'reco-list');
    result.recommendations.forEach(function (reco) {
      var li = el('li');
      li.appendChild(el('h4', null, reco.title));
      li.appendChild(el('p', null, reco.text));
      list.appendChild(li);
    });
    panel.appendChild(list);

    var emergency = el('div', 'callout');
    emergency.appendChild(el('strong', null, 'If you have already clicked, replied or paid'));
    var steps = el('ul');
    [
      'Change the password for the affected account from the service\'s own website or app, and change it anywhere else you reused it.',
      'Run a security scan with the tool built into your operating system, and check your email rules for forwarding rules you did not create.',
      'Tell your IT or security team immediately, and contact your bank straight away if money, card details or bank details were involved.',
      'Report it to your national fraud or cybercrime service. Reporting quickly gives the best chance of recovery and protects others.'
    ].forEach(function (text) { steps.appendChild(el('li', null, text)); });
    emergency.appendChild(steps);
    panel.appendChild(emergency);
  }

  /* ==========================================================
     Rendering: headers and authentication
     ========================================================== */
  function authPill(value) {
    var level = 'status-soft';
    var shown = value || 'not present';
    if (value === 'pass') { level = 'status-pass'; }
    if (value === 'fail' || value === 'permerror' || value === 'temperror') { level = 'status-fail'; }
    return el('span', 'status-pill ' + level, shown);
  }

  function renderHeaders(result) {
    var panel = ui.panelHeaders;
    clear(panel);
    var headers = result.headers;

    if (!headers.present) {
      var missing = el('div', 'callout');
      missing.appendChild(el('strong', null, 'No email headers were found in the text you pasted.'));
      missing.appendChild(el('p', null, 'Without headers the analyser cannot check SPF, DKIM, DMARC or the '
        + 'Reply-To address - often the most decisive evidence there is. If you still have the message, here is how to find them:'));
      var how = el('ul');
      [
        'Gmail: open the message, click the three dots next to Reply, choose "Show original".',
        'Outlook on the web: open the message, click the three dots, choose "View" then "View message source".',
        'Outlook desktop: open the message, then File > Properties - the "Internet headers" box is what you want.',
        'Apple Mail: with the message selected, choose View > Message > All Headers (or Raw Source).'
      ].forEach(function (text) { how.appendChild(el('li', null, text)); });
      missing.appendChild(how);
      missing.appendChild(el('p', null, 'Then paste the whole message, headers included, into the box at the top of the page.'));
      panel.appendChild(missing);
    } else {
      panel.appendChild(el('p', 'panel-intro', headers.fieldCount + ' header field(s) were read from the pasted text.'));

      var auth = headers.auth || {};
      panel.appendChild(el('h3', 'subhead', 'Authentication results'));
      panel.appendChild(el('p', 'panel-intro',
        'SPF, DKIM and DMARC are three ways the receiving mail system checks whether a message really came '
        + 'from the domain it claims. None of them is perfect, but a failure is meaningful evidence.'));

      var authWrap = el('div', 'table-wrap');
      var authTable = el('table');
      authTable.appendChild(el('caption', null, 'Results reported by the receiving mail system'));
      var authBody = el('tbody');
      [
        ['SPF', auth.spf, 'Was the sending server authorised by the domain owner?'],
        ['DKIM', auth.dkim, 'Does the message carry a valid cryptographic signature from that domain?'],
        ['DMARC', auth.dmarc, 'Does the domain owner\'s policy agree with the SPF and DKIM outcomes?']
      ].forEach(function (row) {
        var tr = el('tr');
        tr.appendChild(el('td', 'mono', row[0]));
        var td = el('td');
        td.appendChild(authPill(row[1]));
        tr.appendChild(td);
        tr.appendChild(el('td', null, row[2]));
        authBody.appendChild(tr);
      });
      authTable.appendChild(authBody);
      authWrap.appendChild(authTable);
      panel.appendChild(authWrap);

      if (auth.raw) {
        var raw = el('div', 'evidence');
        raw.appendChild(el('span', 'evidence-label', 'Raw authentication text'));
        raw.appendChild(document.createTextNode(auth.raw));
        panel.appendChild(raw);
      }

      renderHeaderFacts(panel, headers, result);
    }

    renderUrlAndAttachmentLists(panel, result);
  }

  /* The sender details, the routing chain, and the "how to read this" note. */
  function renderHeaderFacts(panel, headers, result) {
    panel.appendChild(el('h3', 'subhead', 'Sender addresses'));
    var facts = el('ul', 'bullet-facts');
    function factRow(label, value) {
      var li = el('li');
      li.appendChild(el('span', 'k', label));
      li.appendChild(el('span', 'v mono', value || 'not present'));
      facts.appendChild(li);
    }
    factRow('From (display name)', headers.from ? headers.from.display : '');
    factRow('From (real address)', headers.from ? headers.from.address : '');
    factRow('Reply-To', headers.replyTo ? headers.replyTo.address : '');
    factRow('Return-Path', headers.returnPath ? headers.returnPath.address : '');
    factRow('Subject', headers.subject || '');
    factRow('Message-ID', headers.messageId || '');
    panel.appendChild(facts);

    if (headers.receivedChain.length) {
      panel.appendChild(el('h3', 'subhead', 'Routing (Received lines)'));
      var chain = el('ul', 'bullet-facts');
      headers.receivedChain.forEach(function (line) {
        var li = el('li');
        li.appendChild(el('span', 'v mono', line));
        chain.appendChild(li);
      });
      panel.appendChild(chain);
    }

    var warn = el('div', 'callout');
    warn.appendChild(el('strong', null, 'How to read this'));
    warn.appendChild(el('p', null, 'A failure here makes it more likely that the sender was forged, but '
      + 'forwarding and mailing lists can also cause failures. A pass only means the domain is genuine - '
      + 'it says nothing about whether the person sending it means you harm.'));
    panel.appendChild(warn);
  }

  /* Links and attachment names, listed as raw evidence for you to inspect. */
  function renderUrlAndAttachmentLists(panel, result) {
    if (result.stats.urls.length) {
      panel.appendChild(el('h3', 'subhead', 'Links found in the text'));
      var linksWrap = el('div', 'table-wrap');
      var linksTable = el('table');
      linksTable.appendChild(el('caption', null, 'Listed for inspection only - do not visit them from here'));
      var linksHead = el('thead');
      var headRow = el('tr');
      headRow.appendChild(el('th', null, 'Real domain'));
      headRow.appendChild(el('th', null, 'Full link'));
      linksHead.appendChild(headRow);
      linksTable.appendChild(linksHead);
      var linksBody = el('tbody');
      result.stats.urls.forEach(function (url) {
        var tr = el('tr');
        tr.appendChild(el('td', 'mono', url.registrable));
        tr.appendChild(el('td', 'mono', url.href));
        linksBody.appendChild(tr);
      });
      linksTable.appendChild(linksBody);
      linksWrap.appendChild(linksTable);
      panel.appendChild(linksWrap);
    }

    if (result.stats.attachmentNames.length) {
      panel.appendChild(el('h3', 'subhead', 'Attachment names found in the text'));
      var namesWrap = el('div', 'table-wrap');
      var namesTable = el('table');
      namesTable.appendChild(el('caption', null,
        'Only names mentioned in the message can be analysed - the files themselves are never opened or uploaded'));
      var namesBody = el('tbody');
      result.stats.attachmentNames.forEach(function (name) {
        var tr = el('tr');
        tr.appendChild(el('td', 'mono', name));
        namesBody.appendChild(tr);
      });
      namesTable.appendChild(namesBody);
      namesWrap.appendChild(namesTable);
      panel.appendChild(namesWrap);
    }
  }

  /* ==========================================================
     Rendering: how scoring works (built from the rule book itself)
     ========================================================== */
  function renderScoringPanel() {
    var panel = ui.panelScoring;
    clear(panel);

    var allRules = rules.allRules();

    panel.appendChild(el('p', 'panel-intro',
      'This is the entire scoring system: ' + allRules.length + ' checks, their point values, and the caps. '
      + 'Nothing is hidden and nothing is decided by a black box. The interface shows the findings by '
      + 'reading this same list, so what you see above is exactly what the code did.'));

    panel.appendChild(el('h3', 'subhead', 'The three risk bands'));
    var bandWrap = el('div', 'table-wrap');
    var bandTable = el('table');
    bandTable.appendChild(el('caption', null, 'Score to classification'));
    var bandHead = el('thead');
    var bh = el('tr');
    ['Score', 'Classification', 'What it means'].forEach(function (t) { bh.appendChild(el('th', null, t)); });
    bandHead.appendChild(bh);
    bandTable.appendChild(bandHead);
    var bandBody = el('tbody');
    var ranges = ['0 to 24', '25 to 54', '55 to 100'];
    rules.BANDS.forEach(function (band, index) {
      var tr = el('tr');
      tr.appendChild(el('td', 'num', ranges[index]));
      var nameCell = el('td');
      nameCell.appendChild(el('span', null, band.label));
      tr.appendChild(nameCell);
      tr.appendChild(el('td', null, band.summary));
      bandBody.appendChild(tr);
    });
    bandTable.appendChild(bandBody);
    bandWrap.appendChild(bandTable);
    panel.appendChild(bandWrap);

    panel.appendChild(el('h3', 'subhead', 'How the maths works'));
    var how = el('ol');
    [
      'Every triggered check adds its points to its category. Points are only ever added, never subtracted.',
      'Each category has a cap, so repeating one trick cannot inflate the score.',
      'The category totals are added together.',
      'The final score is capped at 100.'
    ].forEach(function (text) { how.appendChild(el('li', null, text)); });
    panel.appendChild(how);

    panel.appendChild(el('h3', 'subhead', 'Category caps'));
    var capWrap = el('div', 'table-wrap');
    var capTable = el('table');
    capTable.appendChild(el('caption', null, 'The most each category can contribute'));
    var capHead = el('thead');
    var ch = el('tr');
    ['Category', 'Cap', 'Why it exists'].forEach(function (t) { ch.appendChild(el('th', null, t)); });
    capHead.appendChild(ch);
    capTable.appendChild(capHead);
    var capBody = el('tbody');
    Object.keys(rules.CATEGORIES).forEach(function (id) {
      var category = rules.CATEGORIES[id];
      var tr = el('tr');
      tr.appendChild(el('td', null, category.label));
      tr.appendChild(el('td', 'num', category.cap + ' points'));
      tr.appendChild(el('td', null, category.blurb));
      capBody.appendChild(tr);
    });
    capTable.appendChild(capBody);
    capWrap.appendChild(capTable);
    panel.appendChild(capWrap);

    panel.appendChild(el('h3', 'subhead', 'Every check and its points'));

    Object.keys(rules.CATEGORIES).forEach(function (id) {
      var category = rules.CATEGORIES[id];
      var inCategory = allRules.filter(function (rule) { return rule.category === id; });
      if (!inCategory.length) { return; }

      var heading = el('h4', null, category.label + ' (cap ' + category.cap + ')');
      heading.style.marginTop = '1.1rem';
      panel.appendChild(heading);

      var wrap = el('div', 'table-wrap');
      var table = el('table');
      table.appendChild(el('caption', null, inCategory.length + ' check(s) in this category'));
      var thead = el('thead');
      var hr = el('tr');
      ['Check', 'Points', 'What it looks for'].forEach(function (t) { hr.appendChild(el('th', null, t)); });
      thead.appendChild(hr);
      table.appendChild(thead);
      var tbody = el('tbody');
      inCategory
        .slice()
        .sort(function (a, b) { return b.weight - a.weight; })
        .forEach(function (rule) {
          var tr = el('tr');
          var nameCell = el('td');
          nameCell.appendChild(el('strong', null, rule.title));
          nameCell.appendChild(el('div', 'caption', rule.id));
          tr.appendChild(nameCell);
          tr.appendChild(el('td', 'num', String(rule.weight)));
          tr.appendChild(el('td', null, rule.patterns
            ? 'Text patterns (' + rule.patterns.length + ') - ' + rule.why
            : rule.why));
          tbody.appendChild(tr);
        });
      table.appendChild(tbody);
      wrap.appendChild(table);
      panel.appendChild(wrap);
    });

    var editNote = el('div', 'callout');
    editNote.appendChild(el('strong', null, 'Want to change the scoring?'));
    editNote.appendChild(el('p', null, 'Every check lives in one file: js/rules.js. Each entry has an id, a title, '
      + 'a weight, a plain-English explanation and the patterns it looks for. Add a copy of an existing entry, '
      + 'adjust its points, save the file and reload the page - this table will update itself. README.md walks through it.'));
    panel.appendChild(editNote);
  }

  /* ==========================================================
     Rendering: privacy
     ========================================================== */
  function renderPrivacyPanel() {
    var panel = ui.panelPrivacy;
    clear(panel);

    var headline = el('div', 'callout');
    headline.appendChild(el('strong', null, 'Your email never leaves this device.'));
    headline.appendChild(el('p', null, 'All of the analysis happens inside this browser tab, using code that is '
      + 'part of this page. There is no server to send it to: this website is a set of static files. '
      + 'Nobody - including whoever hosts this page - receives the text you paste.'));
    panel.appendChild(headline);

    panel.appendChild(el('h3', 'subhead', 'What this application does not do'));
    var nots = el('ul', 'checklist');
    [
      'No uploads: your email is never sent to any server.',
      'No AI service or third-party API: the analysis is a local rule engine, so you can read every rule.',
      'No analytics, no telemetry, no error reporting, no tracking pixels.',
      'No cookies and no local or session storage: reload the page and everything is gone.',
      'No external requests at all: no CDN, no web fonts, no images, no scripts loaded from anywhere else.',
      'No accounts, no database, no backend.'
    ].forEach(function (text) { nots.appendChild(el('li', null, text)); });
    panel.appendChild(nots);

    panel.appendChild(el('h3', 'subhead', 'How you can prove it yourself'));
    var steps = el('ol');
    [
      'Press F12 (or Ctrl+Shift+I) to open your browser\'s developer tools and select the Network tab.',
      'Clear the list, then paste an email and press Analyse Email. The panel stays empty - the only requests there will be the four JavaScript files this page loaded when it first opened.',
      'Want to be certain? Turn off your Wi-Fi or unplug the network cable and analyse an email again. It still works, because nothing is being sent anywhere.',
      'Open the Application or Storage tab: this page creates no cookies and no local storage entries.'
    ].forEach(function (text) { steps.appendChild(el('li', null, text)); });
    panel.appendChild(steps);

    panel.appendChild(el('h3', 'subhead', 'A note on the demo emails'));
    panel.appendChild(el('p', null, 'The six demo messages are entirely fictional. They use reserved domains that '
      + 'can never be registered (example.com, example.net and the .example ending) and documentation IP addresses '
      + 'that cannot be reached on the internet (192.0.2.x, 198.51.100.x, 203.0.113.x). The dangerous-looking links '
      + 'are written "defanged" (hxxp://...) - the convention security analysts use when sharing links - so they '
      + 'cannot be clicked by accident. The analyser understands that convention and still inspects them.'));

    panel.appendChild(el('h3', 'subhead', 'Where the trust still sits'));
    panel.appendChild(el('p', null, 'Local analysis removes one risk: your suspicious email being collected by an '
      + 'unknown website. It does not remove every risk. You should still be careful about which copy of this tool '
      + 'you use, and check the code when you can - it is deliberately small, plainly written and free of '
      + 'dependencies, so that reading it is practical rather than theoretical.'));
  }

  /* ==========================================================
     Copy report (clipboard only - no network involved)
     ========================================================== */
  function buildReportText(result) {
    var lines = [];
    lines.push('PHISHING EMAIL ANALYSER - REPORT');
    lines.push('(Generated locally in the browser. Nothing was uploaded.)');
    lines.push('');
    lines.push('Result: ' + result.band.label + ' - score ' + result.score + ' out of 100');
    lines.push('Points before caps: ' + result.scoreBeforeCaps
      + (result.scoreBeforeCaps !== result.score ? ' (reduced by category caps and the 100-point ceiling)' : ''));
    lines.push('Warning signs found: ' + result.findings.length);
    lines.push('');
    lines.push('SUMMARY');
    lines.push(result.summary);
    lines.push('');
    lines.push('WARNING SIGNS');
    if (!result.findings.length) { lines.push('- None of the checks matched.'); }
    result.findings.forEach(function (f) {
      lines.push('- [' + f.categoryLabel + '] ' + f.title + ' (+' + f.weight + ' points)');
      if (f.evidence) { lines.push('    Evidence: ' + f.evidence); }
      if (f.matches && f.matches.length) { lines.push('    Matched: ' + f.matches.join(', ')); }
    });
    lines.push('');
    lines.push('CATEGORY TOTALS');
    result.categories.forEach(function (c) {
      lines.push('- ' + c.label + ': ' + c.applied + ' of a possible ' + c.cap
        + (c.capped ? ' (capped from ' + c.raw + ')' : ''));
    });
    lines.push('');
    lines.push('HEADERS');
    if (!result.headers.present) {
      lines.push('- No headers were pasted, so SPF/DKIM/DMARC could not be checked.');
    } else {
      var auth = result.headers.auth || {};
      lines.push('- SPF: ' + (auth.spf || 'not present'));
      lines.push('- DKIM: ' + (auth.dkim || 'not present'));
      lines.push('- DMARC: ' + (auth.dmarc || 'not present'));
      lines.push('- From: ' + (result.headers.from ? result.headers.from.address : 'not present'));
      lines.push('- Reply-To: ' + (result.headers.replyTo ? result.headers.replyTo.address : 'not present'));
      lines.push('- Return-Path: ' + (result.headers.returnPath ? result.headers.returnPath.address : 'not present'));
    }
    lines.push('');
    lines.push('RECOMMENDED NEXT STEPS');
    result.recommendations.forEach(function (r, index) {
      lines.push((index + 1) + '. ' + r.title);
      lines.push('   ' + r.text);
    });
    lines.push('');
    lines.push('DISCLAIMER');
    lines.push(result.disclaimer);
    lines.push('');
    lines.push('Warning: never click a link or open an attachment in a suspected phishing email just to test it.');
    return lines.join('\n');
  }

  ui.copyBtn.addEventListener('click', function () {
    if (!state.lastResult) { return; }
    var text = buildReportText(state.lastResult);

    function done(ok) {
      ui.copyBtn.textContent = ok ? 'Report copied' : 'Copy failed';
      window.setTimeout(function () { ui.copyBtn.textContent = 'Copy report'; }, 2200);
    }

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { done(true); }, function () { fallbackCopy(text, done); });
    } else {
      fallbackCopy(text, done);
    }
  });

  /* Older-browser fallback. Still entirely local - the clipboard, not the network. */
  function fallbackCopy(text, done) {
    var holder = el('textarea');
    holder.value = text;
    holder.setAttribute('aria-hidden', 'true');
    holder.style.position = 'fixed';
    holder.style.left = '-9999px';
    document.body.appendChild(holder);
    holder.select();
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (err) { ok = false; }
    document.body.removeChild(holder);
    done(ok);
  }

  /* Draw the parts of the page that do not depend on an email, then finish. */
  renderScoringPanel();
  renderPrivacyPanel();
  updateCharCount();
})();