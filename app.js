/* ═══════════════════════════════════════════════════════
   PassIQ — Password Strength Analyser + Secure Generator
   app.js — Full Analysis Engine (Pure Vanilla JS)
   ═══════════════════════════════════════════════════════ */

;(function () {
  'use strict';

  // ─── CONSTANTS ───
  const CHARSETS = {
    UPPER:   'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    LOWER:   'abcdefghijklmnopqrstuvwxyz',
    NUMBERS: '0123456789',
    SYMBOLS: '!@#$%^&*()_+-=[]{}|;:,.<>?'
  };

  const KEYBOARD_WALKS = [
    'qwerty','qwert','werty','asdf','asdfg','zxcv',
    'zxcvb','qazwsx','1qaz','2wsx','qwertyuiop',
    'asdfghjkl','zxcvbnm'
  ];

  const SEQUENTIAL_NUMBERS = [
    '0123','1234','2345','3456','4567','5678',
    '6789','9876','8765','7654','6543','5432',
    '4321','3210'
  ];

  const COMMON_PATTERNS = [
    'password','passwd','pass','admin','login',
    'welcome','monkey','dragon','master','hello',
    'letmein','iloveyou','sunshine','princess',
    'football','shadow','superman','batman',
    'trustno1','abc123','qwerty123','password1',
    '123456','1234567','12345678','123456789'
  ];

  const VAULT_KEY = 'piq_vault';
  const MAX_VAULT = 10;

  // ─── DOM REFS ───
  const $ = (s) => document.querySelector(s);
  const $$ = (s) => document.querySelectorAll(s);

  const els = {
    passwordInput:   $('#password-input'),
    toggleVis:       $('#toggle-visibility'),
    eyeIcon:         $('#eye-icon'),
    charCounter:     $('#char-counter'),
    meterLabel:      $('#meter-label'),
    scoreValue:      $('#score-value'),
    segments:        [1,2,3,4,5].map(i => $(`#seg-${i}`)),
    crackOnline:     $('#crack-online-val'),
    crackOffline:    $('#crack-offline-val'),
    crackGpu:        $('#crack-gpu-val'),
    crackCards:      [
      $('#crack-online'),
      $('#crack-offline'),
      $('#crack-gpu')
    ],
    ruleItems: {
      minLength8:     $('#rule-len8'),
      minLength12:    $('#rule-len12'),
      hasUppercase:   $('#rule-upper'),
      hasLowercase:   $('#rule-lower'),
      hasNumbers:     $('#rule-nums'),
      hasSymbols:     $('#rule-syms'),
      noKeyboardWalk: $('#rule-kb'),
      noCommonPattern:$('#rule-common')
    },
    patternWarnings: $('#pattern-warnings'),
    entropyValue:    $('#entropy-value'),
    entropyFill:     $('#entropy-bar-fill'),
    btnSaveVault:    $('#btn-save-vault'),

    // Generator
    genLength:       $('#gen-length'),
    genLengthPill:   $('#gen-length-pill'),
    genUpper:        $('#gen-upper'),
    genLower:        $('#gen-lower'),
    genNums:         $('#gen-nums'),
    genSyms:         $('#gen-syms'),
    genPasswordText: $('#gen-password-text'),
    genMiniSegments: [1,2,3,4,5].map(i => $(`#gen-seg-${i}`)),
    genMiniLabel:    $('#gen-mini-label'),
    btnReveal:       $('#btn-reveal'),
    btnCopyGen:      $('#btn-copy-gen'),
    btnSendAnalyser: $('#btn-send-analyser'),
    btnGenerate:     $('#btn-generate'),

    // Vault
    vaultList:       $('#vault-list'),
    vaultEmpty:      $('#vault-empty'),

    // Toast
    toastContainer:  $('#toast-container'),

    // Particles
    particles:       $('#particles'),

    inputWrapper:    $('#input-wrapper')
  };

  // ─── STATE ───
  let currentScore = 0;
  let displayedScore = 0;
  let scoreAnimFrame = null;
  let generatedPassword = '';
  let isPasswordRevealed = false;
  let isGenRevealed = false;

  // ═══════════════════════════════════════════
  // CORE ANALYSIS ENGINE
  // ═══════════════════════════════════════════

  /**
   * 1. Calculate entropy in bits
   */
  function calculateEntropy(password) {
    if (!password.length) return 0;
    let poolSize = 0;
    if (/[a-z]/.test(password)) poolSize += 26;
    if (/[A-Z]/.test(password)) poolSize += 26;
    if (/[0-9]/.test(password)) poolSize += 10;
    if (/[^A-Za-z0-9]/.test(password)) poolSize += 32;
    if (poolSize === 0) return 0;
    return password.length * Math.log2(poolSize);
  }

  /**
   * 2. Calculate score 0-100
   */
  function calculateScore(password) {
    if (!password.length) return 0;
    let s = 0;
    const len = password.length;
    const hasLower   = /[a-z]/.test(password);
    const hasUpper   = /[A-Z]/.test(password);
    const hasNum     = /[0-9]/.test(password);
    const hasSym     = /[^A-Za-z0-9]/.test(password);

    // Length scoring
    if (len >= 16)     s += 40;
    else if (len >= 12) s += 30;
    else if (len >= 8)  s += 20;
    else if (len >= 6)  s += 10;

    // Character variety
    if (hasLower) s += 10;
    if (hasUpper) s += 10;
    if (hasNum)   s += 10;
    if (hasSym)   s += 15;

    // Bonuses
    if (hasUpper && hasLower) s += 5;
    if (hasLower && hasUpper && hasNum && hasSym) s += 5;

    // Penalties
    if (hasKeyboardWalk(password)) s -= 20;
    if (hasCommonPattern(password)) s -= 15;
    if (hasLeetspeak(password)) s -= 10;
    if (hasRepeatedChars(password)) s -= 10;
    if (hasSequentialNumbers(password)) s -= 10;

    // Only one type
    const types = [hasLower, hasUpper, hasNum, hasSym].filter(Boolean).length;
    if (types === 1) s -= 5;

    return Math.max(0, Math.min(100, s));
  }

  /**
   * 3. Get strength label
   */
  function getStrengthLabel(score) {
    if (score >= 80) return { label: 'VERY STRONG', color: '#10b981', segments: 5 };
    if (score >= 60) return { label: 'STRONG',      color: '#06b6d4', segments: 4 };
    if (score >= 40) return { label: 'FAIR',         color: '#f59e0b', segments: 3 };
    if (score >= 20) return { label: 'WEAK',         color: '#f97316', segments: 2 };
    return { label: 'VERY WEAK', color: '#ef4444', segments: 1 };
  }

  /**
   * 4. Calculate crack times
   */
  function calculateCrackTime(password) {
    if (!password.length) return { online: '—', offline: '—', gpu: '—' };

    let poolSize = 0;
    if (/[a-z]/.test(password)) poolSize += 26;
    if (/[A-Z]/.test(password)) poolSize += 26;
    if (/[0-9]/.test(password)) poolSize += 10;
    if (/[^A-Za-z0-9]/.test(password)) poolSize += 32;
    if (poolSize === 0) poolSize = 26; // fallback

    // Use logarithmic calculation to avoid Infinity for large passwords
    const logCombinations = password.length * Math.log10(poolSize);

    function formatTime(logSeconds) {
      // logSeconds is log10 of seconds
      if (logSeconds < 0) return 'Instantly';
      if (logSeconds < Math.log10(60)) {
        const secs = Math.pow(10, logSeconds);
        return secs < 1 ? 'Instantly' : `${Math.round(secs)} seconds`;
      }
      if (logSeconds < Math.log10(3600)) {
        return `${Math.round(Math.pow(10, logSeconds) / 60)} minutes`;
      }
      if (logSeconds < Math.log10(86400)) {
        return `${Math.round(Math.pow(10, logSeconds) / 3600)} hours`;
      }
      if (logSeconds < Math.log10(2592000)) {
        return `${Math.round(Math.pow(10, logSeconds) / 86400)} days`;
      }
      if (logSeconds < Math.log10(31536000)) {
        return `${Math.round(Math.pow(10, logSeconds) / 2592000)} months`;
      }
      if (logSeconds < Math.log10(3153600000)) {
        const years = Math.pow(10, logSeconds) / 31536000;
        return `${Math.round(years).toLocaleString()} years`;
      }
      // very large numbers
      const logYears = logSeconds - Math.log10(31536000);
      if (logYears > 6) return 'Centuries';
      const years = Math.pow(10, logYears);
      if (years > 1e6) return 'Centuries';
      return `${Math.round(years).toLocaleString()} years`;
    }

    // Average case: divide total combinations by 2
    const logAvg = logCombinations - Math.log10(2);
    const onlineLogSec  = logAvg - 3;      // 1,000/sec
    const offlineLogSec = logAvg - 9;       // 1 billion/sec
    const gpuLogSec     = logAvg - 11;      // 100 billion/sec

    return {
      online:  formatTime(onlineLogSec),
      offline: formatTime(offlineLogSec),
      gpu:     formatTime(gpuLogSec)
    };
  }

  /**
   * 5. Detect patterns
   */
  function detectPatterns(password) {
    const warnings = [];
    const lower = password.toLowerCase();

    // Keyboard walks
    KEYBOARD_WALKS.forEach(walk => {
      if (lower.includes(walk)) {
        warnings.push({ type: 'keyboard', message: `Keyboard walk detected: '${walk}'` });
      }
    });

    // Sequential numbers
    SEQUENTIAL_NUMBERS.forEach(seq => {
      if (password.includes(seq)) {
        warnings.push({ type: 'sequential', message: `Sequential numbers detected: '${seq}'` });
      }
    });

    // Repeated chars
    const repeatMatch = password.match(/(.)\1{2,}/g);
    if (repeatMatch) {
      repeatMatch.forEach(m => {
        warnings.push({ type: 'repeated', message: `Repeated characters: '${m}'` });
      });
    }

    // Leetspeak
    const leetChecks = [
      { sym: '@',  missing: 'a' },
      { sym: '3',  missing: 'e' },
      { sym: '0',  missing: 'o' },
      { sym: '1',  missing: 'l' },
      { sym: '1',  missing: 'i' },
      { sym: '$',  missing: 's' }
    ];
    leetChecks.forEach(({ sym, missing }) => {
      if (password.includes(sym) && !lower.includes(missing)) {
        warnings.push({ type: 'leet', message: `L33tspeak detected: '${sym}' replacing '${missing}'` });
      }
    });

    // Common patterns
    COMMON_PATTERNS.forEach(pattern => {
      if (lower.includes(pattern)) {
        warnings.push({ type: 'common', message: `Common word detected: '${pattern}'` });
      }
    });

    // De-dupe by message
    const seen = new Set();
    return warnings.filter(w => {
      if (seen.has(w.message)) return false;
      seen.add(w.message);
      return true;
    });
  }

  // Pattern helpers
  function hasKeyboardWalk(pw) {
    const l = pw.toLowerCase();
    return KEYBOARD_WALKS.some(w => l.includes(w));
  }
  function hasCommonPattern(pw) {
    const l = pw.toLowerCase();
    return COMMON_PATTERNS.some(p => l.includes(p));
  }
  function hasLeetspeak(pw) {
    const lower = pw.toLowerCase();
    const checks = [
      { sym: '@', missing: 'a' },
      { sym: '3', missing: 'e' },
      { sym: '0', missing: 'o' },
      { sym: '1', missing: 'l' },
      { sym: '$', missing: 's' }
    ];
    return checks.some(({ sym, missing }) => pw.includes(sym) && !lower.includes(missing));
  }
  function hasRepeatedChars(pw) {
    return /(.)\1{2,}/.test(pw);
  }
  function hasSequentialNumbers(pw) {
    return SEQUENTIAL_NUMBERS.some(s => pw.includes(s));
  }

  /**
   * 6. Check rules
   */
  function checkRules(password) {
    return {
      minLength8:      password.length >= 8,
      minLength12:     password.length >= 12,
      hasUppercase:    /[A-Z]/.test(password),
      hasLowercase:    /[a-z]/.test(password),
      hasNumbers:      /[0-9]/.test(password),
      hasSymbols:      /[^A-Za-z0-9]/.test(password),
      noKeyboardWalk:  !hasKeyboardWalk(password),
      noCommonPattern: !hasCommonPattern(password)
    };
  }

  /**
   * 7. Generate cryptographically secure password
   */
  function generatePassword(length, useUpper, useLower, useNumbers, useSymbols) {
    let charset = '';
    const required = [];

    if (useUpper)   { charset += CHARSETS.UPPER;   required.push(CHARSETS.UPPER); }
    if (useLower)   { charset += CHARSETS.LOWER;   required.push(CHARSETS.LOWER); }
    if (useNumbers) { charset += CHARSETS.NUMBERS; required.push(CHARSETS.NUMBERS); }
    if (useSymbols) { charset += CHARSETS.SYMBOLS; required.push(CHARSETS.SYMBOLS); }

    if (!charset) {
      charset = CHARSETS.LOWER;
      required.push(CHARSETS.LOWER);
    }

    // Build password
    const result = [];

    // Guarantee at least 1 from each required set
    required.forEach(set => {
      const rng = crypto.getRandomValues(new Uint32Array(1))[0];
      result.push(set[rng % set.length]);
    });

    // Fill remaining
    const remaining = length - result.length;
    const rngArr = crypto.getRandomValues(new Uint32Array(Math.max(0, remaining)));
    for (let i = 0; i < remaining; i++) {
      result.push(charset[rngArr[i] % charset.length]);
    }

    // Fisher-Yates shuffle
    for (let i = result.length - 1; i > 0; i--) {
      const j = Math.floor(
        crypto.getRandomValues(new Uint32Array(1))[0] / (2 ** 32) * (i + 1)
      );
      [result[i], result[j]] = [result[j], result[i]];
    }

    return result.join('');
  }

  /**
   * 8. Main analyse function
   */
  function analysePassword(password) {
    const score    = calculateScore(password);
    const strength = getStrengthLabel(score);
    const entropy  = calculateEntropy(password);
    const crack    = calculateCrackTime(password);
    const rules    = checkRules(password);
    const patterns = detectPatterns(password);

    return {
      score,
      label:    strength.label,
      color:    strength.color,
      segments: strength.segments,
      entropy,
      crackTimes: crack,
      rules,
      patterns
    };
  }

  // ═══════════════════════════════════════════
  // VAULT (localStorage)
  // ═══════════════════════════════════════════

  function getVault() {
    try {
      return JSON.parse(localStorage.getItem(VAULT_KEY)) || [];
    } catch {
      return [];
    }
  }

  function saveToVault(password, score, label) {
    const vault = getVault();
    const masked = password[0] + '•'.repeat(Math.max(0, password.length - 2)) + password[password.length - 1];
    vault.unshift({
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
      maskedPassword: masked,
      rawPassword: password,
      score,
      label,
      date: new Date().toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' })
    });
    if (vault.length > MAX_VAULT) vault.pop();
    localStorage.setItem(VAULT_KEY, JSON.stringify(vault));
    renderVault();
    showToast('Saved to vault ✅', 'success');
  }

  function deleteFromVault(id) {
    let vault = getVault().filter(e => e.id !== id);
    localStorage.setItem(VAULT_KEY, JSON.stringify(vault));
    renderVault();
    showToast('Removed from vault 🗑️', 'warning');
  }

  // ═══════════════════════════════════════════
  // UI RENDERING FUNCTIONS
  // ═══════════════════════════════════════════

  /**
   * 13. Render meter segments
   */
  function renderMeter(segments, color) {
    const colors = ['#ef4444', '#f97316', '#f59e0b', '#06b6d4', '#10b981'];
    els.segments.forEach((seg, i) => {
      if (i < segments) {
        seg.classList.add('active');
        seg.style.background = colors[i];
        seg.style.color = colors[i];
      } else {
        seg.classList.remove('active');
        seg.style.background = 'rgba(255,255,255,0.06)';
        seg.style.boxShadow = 'none';
      }
    });
    els.meterLabel.style.color = color;
  }

  /**
   * 14. Animate score counter
   */
  function animateScore(target) {
    if (scoreAnimFrame) cancelAnimationFrame(scoreAnimFrame);
    const start = displayedScore;
    const diff = target - start;
    const duration = 400;
    const startTime = performance.now();

    function step(now) {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
      displayedScore = Math.round(start + diff * eased);
      els.scoreValue.textContent = displayedScore;
      if (progress < 1) {
        scoreAnimFrame = requestAnimationFrame(step);
      }
    }
    scoreAnimFrame = requestAnimationFrame(step);
  }

  /**
   * 15. Render rules checklist
   */
  function renderRules(rules) {
    Object.entries(rules).forEach(([key, passed], i) => {
      const el = els.ruleItems[key];
      if (!el) return;
      const icon = el.querySelector('.rule-icon');
      setTimeout(() => {
        if (passed) {
          el.classList.add('pass');
          el.classList.remove('fail');
          icon.textContent = '✅';
        } else {
          el.classList.add('fail');
          el.classList.remove('pass');
          icon.textContent = '❌';
        }
      }, i * 40); // staggered
    });
  }

  /**
   * 16. Render pattern warnings
   */
  function renderPatternWarnings(patterns) {
    els.patternWarnings.innerHTML = '';
    if (!patterns.length) return;
    patterns.forEach(p => {
      const div = document.createElement('div');
      div.className = 'pattern-warning';
      div.innerHTML = `<span class="pattern-warning-icon">⚠️</span> ${p.message}`;
      els.patternWarnings.appendChild(div);
    });
  }

  /**
   * 17. Render crack times
   */
  function renderCrackTimes(crackTimes) {
    const vals = [crackTimes.online, crackTimes.offline, crackTimes.gpu];
    const elVals = [els.crackOnline, els.crackOffline, els.crackGpu];
    const dangerTerms = ['Instantly', 'seconds', 'minutes'];
    const warnTerms = ['hours', 'days', 'months'];

    vals.forEach((val, i) => {
      elVals[i].textContent = val;
      const card = els.crackCards[i];
      card.classList.remove('crack-safe', 'crack-warn', 'crack-danger');
      if (dangerTerms.some(t => val.includes(t)) || val === '—') {
        card.classList.add('crack-danger');
      } else if (warnTerms.some(t => val.includes(t))) {
        card.classList.add('crack-warn');
      } else {
        card.classList.add('crack-safe');
      }
    });
  }

  /**
   * 18. Render entropy
   */
  function renderEntropy(entropy) {
    els.entropyValue.textContent = entropy.toFixed(1);
    const pct = Math.min(100, (entropy / 128) * 100); // 128 bits = full bar
    els.entropyFill.style.width = pct + '%';

    let color;
    if (entropy < 28)      color = '#ef4444';
    else if (entropy < 36) color = '#f59e0b';
    else if (entropy < 60) color = '#06b6d4';
    else                   color = '#10b981';
    els.entropyFill.style.background = color;
  }

  /**
   * 19. Render vault
   */
  function renderVault() {
    const vault = getVault();
    els.vaultList.innerHTML = '';
    if (vault.length === 0) {
      els.vaultEmpty.classList.remove('hidden');
      return;
    }
    els.vaultEmpty.classList.add('hidden');

    vault.forEach(entry => {
      const strength = getStrengthLabel(entry.score);
      const el = document.createElement('div');
      el.className = 'vault-entry';
      el.innerHTML = `
        <span class="vault-masked">${entry.maskedPassword}</span>
        <span class="vault-badge" style="
          background: ${strength.color}22;
          color: ${strength.color};
          border: 1px solid ${strength.color}44;
        ">${entry.label}</span>
        <span class="vault-score">${entry.score}/100</span>
        <span class="vault-date">${entry.date}</span>
        <button class="vault-btn vault-copy-btn" data-password="${encodeURIComponent(entry.rawPassword)}" aria-label="Copy password" type="button">
          <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>
        </button>
        <button class="vault-btn vault-delete-btn" data-id="${entry.id}" aria-label="Delete entry" type="button">
          <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></svg>
        </button>
      `;
      els.vaultList.appendChild(el);
    });

    // Bind events
    els.vaultList.querySelectorAll('.vault-copy-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        copyToClipboard(decodeURIComponent(btn.dataset.password));
      });
    });
    els.vaultList.querySelectorAll('.vault-delete-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        deleteFromVault(btn.dataset.id);
      });
    });
  }

  /**
   * 20. Show toast
   */
  function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    els.toastContainer.appendChild(toast);
    setTimeout(() => {
      if (toast.parentNode) toast.remove();
    }, 3000);
  }

  /**
   * 21. Typewriter effect
   */
  function typewriterEffect(element, text, speed = 20) {
    element.textContent = '';
    element.classList.remove('blurred');
    let idx = 0;
    function tick() {
      if (idx < text.length) {
        element.textContent += text[idx];
        idx++;
        setTimeout(tick, speed);
      }
    }
    tick();
  }

  /**
   * 22. Debounce
   */
  function debounce(fn, delay) {
    let timer;
    return function (...args) {
      clearTimeout(timer);
      timer = setTimeout(() => fn.apply(this, args), delay);
    };
  }

  /**
   * Copy to clipboard
   */
  function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
      showToast('Copied! ✅', 'success');
    }).catch(() => {
      // Fallback
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      showToast('Copied! ✅', 'success');
    });
  }

  /**
   * Set input glow class
   */
  function setInputGlow(score, isEmpty) {
    const input = els.passwordInput;
    input.classList.remove('glow-red', 'glow-amber', 'glow-cyan', 'glow-green');
    if (isEmpty) return;
    if (score < 30)      input.classList.add('glow-red');
    else if (score < 60) input.classList.add('glow-amber');
    else if (score < 80) input.classList.add('glow-cyan');
    else                 input.classList.add('glow-green');
  }

  // ═══════════════════════════════════════════
  // MAIN ANALYSIS HANDLER
  // ═══════════════════════════════════════════

  function handleAnalysis() {
    const pw = els.passwordInput.value;
    els.charCounter.textContent = `${pw.length} / ∞`;

    if (!pw.length) {
      // Reset everything
      setInputGlow(0, true);
      renderMeter(0, '#475569');
      els.meterLabel.textContent = 'ENTER A PASSWORD';
      els.meterLabel.style.color = '#475569';
      animateScore(0);
      renderCrackTimes({ online: '—', offline: '—', gpu: '—' });
      renderRules({
        minLength8: false, minLength12: false,
        hasUppercase: false, hasLowercase: false,
        hasNumbers: false, hasSymbols: false,
        noKeyboardWalk: false, noCommonPattern: false
      });
      renderPatternWarnings([]);
      renderEntropy(0);
      els.btnSaveVault.disabled = true;
      return;
    }

    const result = analysePassword(pw);

    setInputGlow(result.score, false);
    renderMeter(result.segments, result.color);
    els.meterLabel.textContent = result.label;
    animateScore(result.score);
    renderCrackTimes(result.crackTimes);
    renderRules(result.rules);
    renderPatternWarnings(result.patterns);
    renderEntropy(result.entropy);
    els.btnSaveVault.disabled = false;
    currentScore = result.score;
  }

  const debouncedAnalysis = debounce(handleAnalysis, 50);

  // ═══════════════════════════════════════════
  // GENERATOR UI HANDLER
  // ═══════════════════════════════════════════

  function handleGenerate() {
    const length = parseInt(els.genLength.value);
    const pw = generatePassword(
      length,
      els.genUpper.checked,
      els.genLower.checked,
      els.genNums.checked,
      els.genSyms.checked
    );
    generatedPassword = pw;
    isGenRevealed = false;
    els.genPasswordText.classList.add('blurred');
    typewriterEffect(els.genPasswordText, pw, 18);
    // After typewriter, re-blur
    setTimeout(() => {
      if (!isGenRevealed) {
        els.genPasswordText.classList.add('blurred');
      }
    }, pw.length * 18 + 100);

    // Mini strength preview
    const result = analysePassword(pw);
    const colors = ['#ef4444', '#f97316', '#f59e0b', '#06b6d4', '#10b981'];
    els.genMiniSegments.forEach((seg, i) => {
      if (i < result.segments) {
        seg.style.background = colors[i];
      } else {
        seg.style.background = 'rgba(255,255,255,0.06)';
      }
    });
    els.genMiniLabel.textContent = result.label;
    els.genMiniLabel.style.color = result.color;
  }

  // ═══════════════════════════════════════════
  // PARTICLES
  // ═══════════════════════════════════════════

  function createParticles() {
    const count = 14;
    for (let i = 0; i < count; i++) {
      const p = document.createElement('div');
      p.className = 'particle';
      const size = Math.random() * 3 + 2;
      p.style.width = size + 'px';
      p.style.height = size + 'px';
      p.style.left = Math.random() * 100 + '%';
      p.style.top = (80 + Math.random() * 40) + '%';
      p.style.animationDuration = (8 + Math.random() * 12) + 's';
      p.style.animationDelay = (Math.random() * 8) + 's';
      const hue = Math.random() > 0.5 ? '260' : '187'; // purple or cyan
      p.style.background = `hsla(${hue}, 70%, 60%, 0.3)`;
      els.particles.appendChild(p);
    }
  }

  // ═══════════════════════════════════════════
  // EVENT BINDINGS
  // ═══════════════════════════════════════════

  function init() {
    // Init Lucide icons
    if (window.lucide) lucide.createIcons();

    // Particles
    createParticles();

    // Password input
    els.passwordInput.addEventListener('input', debouncedAnalysis);

    // Toggle visibility
    els.toggleVis.addEventListener('click', () => {
      isPasswordRevealed = !isPasswordRevealed;
      els.passwordInput.type = isPasswordRevealed ? 'text' : 'password';
      // Toggle icon
      const icon = els.toggleVis.querySelector('i');
      if (icon) {
        icon.setAttribute('data-lucide', isPasswordRevealed ? 'eye-off' : 'eye');
        lucide.createIcons();
      }
    });

    // Save to vault
    els.btnSaveVault.addEventListener('click', () => {
      const pw = els.passwordInput.value;
      if (!pw) return;
      const result = analysePassword(pw);
      saveToVault(pw, result.score, result.label);
    });

    // Generator: length slider
    els.genLength.addEventListener('input', () => {
      els.genLengthPill.textContent = els.genLength.value + ' chars';
    });

    // Generate button
    els.btnGenerate.addEventListener('click', handleGenerate);

    // Reveal/hide generated password
    els.btnReveal.addEventListener('click', () => {
      isGenRevealed = !isGenRevealed;
      if (isGenRevealed) {
        els.genPasswordText.classList.remove('blurred');
        els.btnReveal.innerHTML = '<i data-lucide="eye-off"></i> Hide';
      } else {
        els.genPasswordText.classList.add('blurred');
        els.btnReveal.innerHTML = '<i data-lucide="eye"></i> Reveal';
      }
      lucide.createIcons();
    });

    // Copy generated
    els.btnCopyGen.addEventListener('click', () => {
      if (!generatedPassword) return;
      copyToClipboard(generatedPassword);
    });

    // Send to analyser
    els.btnSendAnalyser.addEventListener('click', () => {
      if (!generatedPassword) return;
      els.passwordInput.value = generatedPassword;
      els.passwordInput.type = 'text';
      isPasswordRevealed = true;
      const icon = els.toggleVis.querySelector('i');
      if (icon) {
        icon.setAttribute('data-lucide', 'eye-off');
        lucide.createIcons();
      }
      handleAnalysis();
      // Scroll to analyser
      document.getElementById('analyser-section').scrollIntoView({ behavior: 'smooth' });
      showToast('Sent to analyser ↑', 'info');
    });

    // Render vault on load
    renderVault();

    // Initial state — set rules to neutral
    handleAnalysis();
  }

  // ─── BOOT ───
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
