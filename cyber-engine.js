/**
 * CYBER SECURITY PLATFORM - CORE REAL-TIME ENGINE
 * Live Heuristic Detection, SOC Telemetry Feed, URL Hunter & Radar Visualizer
 */

(function (window) {
  'use strict';

  // --- Sound Synthesizer (Web Audio API) ---
  let audioCtx = null;
  let soundEnabled = true;

  function initAudio() {
    if (!audioCtx && (window.AudioContext || window.webkitAudioContext)) {
      audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    }
  }

  function playCyberSound(type) {
    if (!soundEnabled) return;
    try {
      initAudio();
      if (!audioCtx) return;
      if (audioCtx.state === 'suspended') {
        audioCtx.resume();
      }
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      osc.connect(gain);
      gain.connect(audioCtx.destination);
      const now = audioCtx.currentTime;

      if (type === 'critical') {
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(880, now);
        osc.frequency.exponentialRampToValueAtTime(440, now + 0.18);
        gain.gain.setValueAtTime(0.08, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.18);
        osc.start(now);
        osc.stop(now + 0.18);
      } else if (type === 'ping') {
        osc.type = 'sine';
        osc.frequency.setValueAtTime(1400, now);
        gain.gain.setValueAtTime(0.03, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.08);
        osc.start(now);
        osc.stop(now + 0.08);
      } else if (type === 'success') {
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(523.25, now);
        osc.frequency.setValueAtTime(659.25, now + 0.07);
        gain.gain.setValueAtTime(0.05, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.2);
        osc.start(now);
        osc.stop(now + 0.2);
      }
    } catch (e) {
      // Audio autoplay policy or unavailable
    }
  }

  // --- Session & History Manager ---
  const STORAGE_USER_KEY = 'cs_platform_user';
  const STORAGE_HISTORY_KEY = 'cs_platform_history';

  const Auth = {
    getUser() {
      try {
        const u = localStorage.getItem(STORAGE_USER_KEY);
        return u ? JSON.parse(u) : null;
      } catch (e) {
        return null;
      }
    },
    setUser(user) {
      localStorage.setItem(STORAGE_USER_KEY, JSON.stringify(user));
    },
    logout() {
      localStorage.removeItem(STORAGE_USER_KEY);
    },
    loginAsGuest() {
      const guest = {
        name: 'SOC Analyst (Guest)',
        email: 'analyst.demo@cyberguard.gov',
        role: 'Tier-1 Security Analyst',
        loggedInAt: new Date().toISOString()
      };
      this.setUser(guest);
      return guest;
    }
  };

  const HistoryManager = {
    getHistory() {
      try {
        const h = localStorage.getItem(STORAGE_HISTORY_KEY);
        return h ? JSON.parse(h) : [];
      } catch (e) {
        return [];
      }
    },
    addScan(scan) {
      const history = this.getHistory();
      history.unshift({
        id: 'SC-' + Math.floor(100000 + Math.random() * 900000),
        timestamp: new Date().toISOString(),
        ...scan
      });
      if (history.length > 50) history.pop();
      try {
        localStorage.setItem(STORAGE_HISTORY_KEY, JSON.stringify(history));
      } catch (e) {}
    },
    clear() {
      localStorage.removeItem(STORAGE_HISTORY_KEY);
    }
  };

  // --- Multi-Factor Scam Detection Rules ---
  const SCAM_PATTERNS = {
    digitalArrest: {
      category: 'Digital Arrest / Authority Impersonation',
      severity: 'CRITICAL',
      weight: 45,
      regex: /digital arrest|cbi|enforcement directorate|\bed\b.*arrest|narcotics.*(courier|package|customs)|video call.*arrest|police.*warrant|supreme court.*order|cyber crime cell.*arrest|dcp.*crime branch|stay on (this|the) video call/i,
      advisory: 'Digital arrest is a 100% FRAUD tactic. Indian law enforcement, CBI, Police, or Courts NEVER place anyone under digital arrest or conduct interrogations via Skype/WhatsApp video calls.'
    },
    bankingKyc: {
      category: 'Banking / UPI / KYC Suspension Trap',
      severity: 'CRITICAL',
      weight: 40,
      regex: /sbi yono|hdfc.*kyc|icici.*block|account.*(blocked|suspended|freeze)|pan card.*(expire|link|update)|electricity.*(disconnect|power cut|tonight)|lottery.*(won|crore|lakh)|kbc.*(lottery|winner)|claim.*reward.*upi|enter.*(mpin|upi pin)/i,
      advisory: 'Banks & electricity boards NEVER send SMS with APK download links or ask for UPI PINs to receive money. Never enter your UPI PIN to receive funds.'
    },
    remoteAccessApk: {
      category: 'Malicious APK / Remote Access Trojan',
      severity: 'CRITICAL',
      weight: 50,
      regex: /download.*\.apk|install.*\.apk|anydesk|teamviewer|rustdesk|quicksupport|screen share.*app|support tool.*apk/i,
      advisory: 'CRITICAL DANGER: Installing APK files from SMS/WhatsApp or installing AnyDesk gives fraudsters total remote control of your phone and bank accounts.'
    },
    courierCustoms: {
      category: 'Courier / Customs Extortion',
      severity: 'HIGH',
      weight: 35,
      regex: /parcel.*(customs|seized|illegal|held)|courier.*(fee|clearance|fine)|fedex.*(package|narcotics)|bluedart.*(hold|customs)|pay.*clearance fee/i,
      advisory: 'Legitimate couriers do not call demanding instant fee transfers or claiming contraband drugs in unattended parcels.'
    },
    credentialHarvesting: {
      category: 'OTP & Credential Theft',
      severity: 'CRITICAL',
      weight: 45,
      regex: /share.*(otp|one[- ]time password)|forward.*(otp|message|sms)|provide.*(cvv|atm pin|password)/i,
      advisory: 'NEVER share OTPs or forward SMS. OTPs are the final barrier protecting your funds.'
    },
    urgencyPressure: {
      category: 'Psychological Urgency & Coercion',
      severity: 'HIGH',
      weight: 25,
      regex: /urgent|immediately|within.*(hour|minute|2 hours)|act now|last chance|final notice|immediate legal action|warrant issued/i,
      advisory: 'High urgency is intentionally designed by fraudsters to induce panic and prevent you from consulting friends or family.'
    },
    suspiciousLinks: {
      category: 'Deceptive / Phishing Link',
      severity: 'HIGH',
      weight: 30,
      regex: /bit\.ly|tinyurl|[a-z0-9]+\.(xyz|top|buzz|cfd|club|info|live|online)\b|http:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i,
      advisory: 'Links with shortened domains (.bit.ly) or suspicious TLDs (.xyz, .top) frequently lead to fraudulent phishing forms.'
    },
    jobTaskScam: {
      category: 'Work From Home / Telegram Task Scam',
      severity: 'HIGH',
      weight: 35,
      regex: /work from home|part[- ]time job|telegram.*task|like.*youtube.*video|daily income.*(3000|5000|10000)|prepaid task|deposit.*security fee/i,
      advisory: 'Genuine companies never require candidates to deposit advance fees or pay money to "unlock" tasks on Telegram.'
    },
    genericGreeting: {
      category: 'Generic Mass-Mail Greeting',
      severity: 'HIGH',
      weight: 15,
      regex: /dear (customer|user|valued customer|sir\/madam|account holder)/i,
      advisory: 'Legitimate banks and services address you by name. A generic "Dear Customer" greeting is a common sign of a mass-sent phishing email.'
    },
    spoofedSender: {
      category: 'Spoofed Sender / Lookalike Domain',
      severity: 'CRITICAL',
      weight: 30,
      regex: /[a-z0-9.+-]+@[a-z0-9.-]+\.(xyz|top|buzz|cfd|club|info|live|online|ru|cn|support|verify)\b/i,
      advisory: 'The sender address uses a low-reputation or lookalike domain. Genuine organizations send email only from their official registered domain.'
    }
  };

  // --- Scam Analyzer Engine ---
  function analyzeScam(text) {
    if (!text || !text.trim()) {
      return {
        level: 'EMPTY',
        score: 0,
        urgencyScore: 0,
        matches: [],
        categories: [],
        advisory: 'Paste or type a message to inspect.'
      };
    }

    const cleanText = text.trim();
    let totalScore = 0;
    const matches = [];
    const categories = [];

    for (const [key, rule] of Object.entries(SCAM_PATTERNS)) {
      if (rule.regex.test(cleanText)) {
        totalScore += rule.weight;
        categories.push(rule.category);
        matches.push({
          ruleKey: key,
          category: rule.category,
          severity: rule.severity,
          advisory: rule.advisory
        });
      }
    }

    // Urgency heuristic check
    let urgencyScore = 0;
    if (/immediately|within \d+ (hour|minute)|urgent|last chance/i.test(cleanText)) {
      urgencyScore = 85;
    } else if (/today|soon|action required/i.test(cleanText)) {
      urgencyScore = 45;
    }

    // Normalize score to 0-100
    const finalScore = Math.min(100, Math.max(0, totalScore));

    let level = 'SAFE';
    let levelTitle = 'Likely Safe';
    let badgeClass = 'tag-safe';

    if (finalScore >= 60 || matches.some(m => m.severity === 'CRITICAL')) {
      level = 'CRITICAL';
      levelTitle = 'Critical High-Risk Scam';
      badgeClass = 'tag-critical';
    } else if (finalScore >= 25 || matches.length > 0) {
      level = 'CAUTION';
      levelTitle = 'Suspicious / Caution';
      badgeClass = 'tag-high';
    }

    return {
      level,
      levelTitle,
      badgeClass,
      score: finalScore,
      urgencyScore,
      matches,
      categories,
      timestamp: new Date().toLocaleTimeString()
    };
  }

  // --- Real-time Token Highlighter ---
  function highlightScamTokens(text) {
    if (!text) return '';
    // Escape HTML first
    let escaped = text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');

    // High risk keywords
    const highRiskWords = [
      'digital arrest', 'cbi', 'enforcement directorate', 'narcotics', 'video call', 'arrest warrant',
      'police', 'warrant', 'supreme court', 'sbi yono', 'pan card', 'electricity', 'disconnect',
      'lottery', 'kbc', 'anydesk', 'teamviewer', 'quicksupport', '\\.apk', 'share otp', 'forward otp',
      'one[- ]time password', 'cvv', 'atm pin', 'telegram task', 'work from home'
    ];
    // Caution words
    const cautionWords = [
      'urgent', 'immediately', 'within 2 hours', 'clearance fee', 'parcel', 'customs', 'kyc', 'update',
      'suspended', 'blocked', 'claim reward', 'winner', 'act now', 'click here'
    ];

    const highRe = new RegExp(`\\b(${highRiskWords.join('|')})\\b`, 'gi');
    escaped = escaped.replace(highRe, '<mark class="token-high">$1</mark>');

    const cautionRe = new RegExp(`\\b(${cautionWords.join('|')})\\b`, 'gi');
    escaped = escaped.replace(cautionRe, '<mark class="token-caution">$1</mark>');

    return escaped;
  }

  // --- Complaint Formatter ---
  function generateComplaintDraft(text, analysis) {
    const now = new Date();
    const incidentTime = now.toLocaleDateString() + ' ' + now.toLocaleTimeString();
    const categories = analysis.categories.length ? analysis.categories.join(', ') : 'Unspecified Phishing Attempt';
    
    return `================================================================================
OFFICIAL CYBER FRAUD INCIDENT REPORT DRAFT
Intended for: National Cyber Crime Reporting Portal (1930 / cybercrime.gov.in)
Platform: Cyber Security Awareness & Intelligence Platform (Course 1BCP308)
================================================================================

1. INCIDENT METADATA:
   - Generated On: ${incidentTime}
   - Assessed Risk Level: ${analysis.levelTitle} (Risk Index: ${analysis.score}/100)
   - Identified Scam Category: ${categories}
   - Applicable Indian Legal Framework: 
     * Information Technology Act, 2000 (Section 66D - Cheating by Personation)
     * Indian Penal Code / BNS (Sections 419, 420 - Impersonation & Fraud)

2. SUSPECT COMMUNICATION TRANSCRIPT:
--------------------------------------------------------------------------------
"${text.replace(/"/g, "'")}"
--------------------------------------------------------------------------------

3. EVIDENCE & HEURISTIC FINDINGS:
   - Detected Patterns: ${analysis.matches.map(m => m.category).join('; ') || 'Heuristic pattern threshold match'}
   - Psychological Pressure Indicators: ${analysis.urgencyScore > 50 ? 'Severe urgency coercion detected' : 'Standard outreach'}
   - Recommended Police Containment: ${analysis.matches.map(m => m.advisory).join('\n   - ') || 'Block sender and monitor bank statements'}

4. IMMEDIATE VICTIM DIRECTIVES:
   - Do NOT transfer funds, share OTP, or join video calls.
   - Dial 1930 immediately if money has been deducted to freeze beneficiary accounts.
   - File this draft complaint at https://cybercrime.gov.in.

================================================================================`;
  }

  // --- URL & Domain Threat Hunter ---
  const LEGIT_BRANDS = [
    'sbi.co.in', 'onlinesbi.sbi', 'hdfcbank.com', 'icicibank.com', 'axisbank.com', 'pnbindia.in',
    'paytm.com', 'phonepe.com', 'google.com', 'apple.com', 'microsoft.com', 'amazon.in', 'flipkart.com',
    'incometax.gov.in', 'cybercrime.gov.in', 'indiapost.gov.in', 'uidai.gov.in'
  ];

  const RISKY_TLDS = ['.xyz', '.top', '.buzz', '.cfd', '.work', '.click', '.club', '.live', '.online', '.site', '.monster', '.rest'];

  function analyzeUrl(rawUrl) {
    if (!rawUrl || !rawUrl.trim()) return null;
    let url = rawUrl.trim();
    if (!/^https?:\/\//i.test(url)) {
      url = 'https://' + url;
    }

    let parsed = null;
    try {
      parsed = new URL(url);
    } catch (e) {
      return {
        valid: false,
        error: 'Invalid URL format'
      };
    }

    const host = parsed.hostname.toLowerCase();
    const pathname = parsed.pathname.toLowerCase();
    let riskScore = 0;
    const flags = [];

    // IP address host check
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
      riskScore += 45;
      flags.push('Direct IP Address used as host (High Phishing Risk)');
    }

    // Risky TLD check
    const matchedTld = RISKY_TLDS.find(tld => host.endsWith(tld));
    if (matchedTld) {
      riskScore += 35;
      flags.push(`Suspicious low-reputation top-level domain (${matchedTld})`);
    }

    // Brand impersonation check
    const targetBrands = ['sbi', 'hdfc', 'icici', 'paytm', 'phonepe', 'indiapost', 'netflix', 'amazon'];
    for (const b of targetBrands) {
      if (host.includes(b) && !LEGIT_BRANDS.some(l => host === l || host.endsWith('.' + l))) {
        riskScore += 50;
        flags.push(`Brand Impersonation / Typosquatting of "${b.toUpperCase()}" on unauthorized domain`);
        break;
      }
    }

    // Keyword traps in path or subdomain
    if (/kyc|update|login|verify|account|claim|reward|free|gift|apk/i.test(host + pathname)) {
      riskScore += 20;
      flags.push('Deceptive credential harvesting keywords in URL path/host');
    }

    // Excessive subdomain depth
    const subdomains = host.split('.');
    if (subdomains.length > 3) {
      riskScore += 15;
      flags.push(`Excessive subdomain depth (${subdomains.length} parts) common in obfuscated phishing`);
    }

    const finalScore = Math.min(100, riskScore);
    let verdict = 'Safe Link';
    let verdictClass = 'tag-safe';

    if (finalScore >= 50) {
      verdict = 'Malicious / Phishing URL';
      verdictClass = 'tag-critical';
    } else if (finalScore >= 20) {
      verdict = 'Suspicious Link';
      verdictClass = 'tag-high';
    }

    return {
      valid: true,
      url,
      host,
      pathname,
      protocol: parsed.protocol,
      score: finalScore,
      verdict,
      verdictClass,
      flags,
      isLegitBrand: LEGIT_BRANDS.some(l => host === l || host.endsWith('.' + l))
    };
  }

  // --- APK Source & Permission Risk Scanner ---
  const DANGEROUS_PERMISSIONS = [
    { key: 'read sms', label: 'Read SMS' },
    { key: 'receive sms', label: 'Receive SMS' },
    { key: 'accessibility', label: 'Accessibility Service' },
    { key: 'device admin', label: 'Device Administrator' },
    { key: 'draw over other apps', label: 'Display Over Other Apps (Overlay)' },
    { key: 'overlay', label: 'Display Over Other Apps (Overlay)' },
    { key: 'call log', label: 'Read Call Log' },
    { key: 'contacts', label: 'Read Contacts' }
  ];

  function analyzeApk(rawSource, rawPermissions) {
    const source = (rawSource || '').trim();
    const permsText = (rawPermissions || '').toLowerCase();
    if (!source && !permsText) return null;

    let score = 0;
    const flags = [];
    const lowerSource = source.toLowerCase();

    const fromPlayStore = /play\.google\.com/i.test(source);

    if (/\.apk(\?|$|\s)/i.test(source) && !fromPlayStore) {
      score += 30;
      flags.push('Sideloaded .apk file — not distributed via the official Google Play Store');
    }

    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(lowerSource.replace(/^https?:\/\//, ''))) {
      score += 35;
      flags.push('APK hosted directly on a raw IP address — a strong phishing/malware signal');
    }

    const matchedTld = RISKY_TLDS.find(tld => lowerSource.includes(tld));
    if (matchedTld) {
      score += 25;
      flags.push(`Hosted on a low-reputation top-level domain (${matchedTld})`);
    }

    if (/sbi|hdfc|icici|kyc|reward|cashback|refund|electricity|power|update|verify|gov|customs|courier/i.test(lowerSource) && !fromPlayStore) {
      score += 30;
      flags.push('Filename/source impersonates a bank, government, or utility brand — common banking-trojan naming pattern');
    }

    const matchedPerms = DANGEROUS_PERMISSIONS.filter(p => permsText.includes(p.key));
    const uniqueLabels = [...new Set(matchedPerms.map(p => p.label))];
    if (uniqueLabels.length >= 2) {
      score += 40;
      flags.push(`Dangerous permission combination requested (${uniqueLabels.join(', ')}) — classic banking-trojan pattern used to intercept OTPs and control the screen`);
    } else if (uniqueLabels.length === 1) {
      score += 20;
      flags.push(`Requests a high-risk permission (${uniqueLabels[0]}) rarely needed by legitimate utility apps`);
    }

    const finalScore = Math.min(100, score);
    let verdict = 'Likely Safe';
    let verdictClass = 'tag-safe';
    if (finalScore >= 50) {
      verdict = 'Malicious / High-Risk APK';
      verdictClass = 'tag-critical';
    } else if (finalScore >= 20) {
      verdict = 'Suspicious APK';
      verdictClass = 'tag-high';
    }

    return {
      valid: true,
      source,
      fromPlayStore,
      score: finalScore,
      verdict,
      verdictClass,
      flags
    };
  }

  // --- Password Entropy & Crack-Time Vault ---
  function analyzePassword(pwd) {
    if (!pwd) {
      return { score: 0, entropy: 0, crackTime: 'Instant', label: 'None', color: 'var(--text-dim)' };
    }

    let pool = 0;
    if (/[a-z]/.test(pwd)) pool += 26;
    if (/[A-Z]/.test(pwd)) pool += 26;
    if (/[0-9]/.test(pwd)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(pwd)) pool += 33;

    const length = pwd.length;
    const entropy = Math.round(length * (Math.log2(pool || 1)));

    // Common weak checks
    const isCommon = /^(password|123456|qwerty|admin|india|welcome|password123)$/i.test(pwd);

    let crackTime = 'Instant';
    let label = 'Very Weak';
    let color = 'var(--rose)';

    if (isCommon || entropy < 28) {
      crackTime = '< 0.001 seconds';
      label = 'Critically Weak';
      color = 'var(--rose)';
    } else if (entropy < 40) {
      crackTime = '2.4 seconds';
      label = 'Weak';
      color = 'var(--amber)';
    } else if (entropy < 58) {
      crackTime = '3 weeks';
      label = 'Moderate';
      color = 'var(--cyan)';
    } else if (entropy < 75) {
      crackTime = '400 years';
      label = 'Strong';
      color = 'var(--violet)';
    } else {
      crackTime = '2.8 million years';
      label = 'Quantum-Resistant';
      color = 'var(--emerald)';
    }

    return {
      length,
      entropy,
      crackTime,
      label,
      color,
      hasUpper: /[A-Z]/.test(pwd),
      hasLower: /[a-z]/.test(pwd),
      hasNum: /[0-9]/.test(pwd),
      hasSym: /[^a-zA-Z0-9]/.test(pwd)
    };
  }

  // --- Simulated Live SOC Telemetry Stream ---
  const SOC_REGIONS = ['Delhi NCR', 'Mumbai Metro', 'Bengaluru Hub', 'Hyderabad Cyberabad', 'Kolkata Sector V', 'Jaipur Node', 'Jamtara Outpost', 'Mewat Cyber Gateway', 'Ahmedabad SOC'];

  const SOC_THREAT_TEMPLATES = [
    {
      title: 'Digital Arrest Video Scam Intercepted',
      desc: 'Extortion ring impersonating ED Director using WhatsApp video & fake police warrant backdrop.',
      vector: 'VoIP Relay / WhatsApp',
      level: 'CRITICAL',
      tagClass: 'tag-critical'
    },
    {
      title: 'Malicious SBI YONO APK Dropper Blocked',
      desc: 'SMS phishing wave distributing "sbi-rewards-v3.apk" containing banking trojan.',
      vector: 'SMS Bulk Smishing',
      level: 'CRITICAL',
      tagClass: 'tag-critical'
    },
    {
      title: 'Electricity Bill Disconnection Phishing Wave',
      desc: 'Targeted SMS sent to domestic meters threatening power cutoff within 2 hours.',
      vector: 'Regional Telecom Gateway',
      level: 'HIGH',
      tagClass: 'tag-high'
    },
    {
      title: 'Fake FedEx Courier Clearance Traps Flagged',
      desc: 'Extortion calls claiming intercepted parcel in Mumbai airport with customs penalty.',
      vector: 'Spoofed Caller ID',
      level: 'HIGH',
      tagClass: 'tag-high'
    },
    {
      title: 'Telegram Task / Work-From-Home Scam Campaign',
      desc: 'Fraudulent merchant group promising ₹4,500/day for YouTube video likes.',
      vector: 'Telegram Bot API',
      level: 'MEDIUM',
      tagClass: 'tag-medium'
    },
    {
      title: 'Typosquatted Banking Domain Takedown Request',
      desc: 'Automated defense quarantine issued for "onlinesbi-kyc-auth.top".',
      vector: 'DNS Sinkhole',
      level: 'HIGH',
      tagClass: 'tag-high'
    }
  ];

  class TelemetryStream {
    constructor() {
      this.listeners = [];
      this.running = false;
      this.timer = null;
      this.stats = {
        totalIntercepted: 14829,
        highRiskBlocked: 3912,
        avgLatencyMs: 14,
        defconLevel: 2
      };
    }

    subscribe(fn) {
      this.listeners.push(fn);
    }

    start() {
      if (this.running) return;
      this.running = true;
      this._scheduleNext();
    }

    pause() {
      this.running = false;
      if (this.timer) clearTimeout(this.timer);
    }

    toggle() {
      if (this.running) this.pause();
      else this.start();
      return this.running;
    }

    _scheduleNext() {
      if (!this.running) return;
      const delay = 2600 + Math.random() * 2400; // 2.6s - 5s
      this.timer = setTimeout(() => {
        this._generateEvent();
        this._scheduleNext();
      }, delay);
    }

    _generateEvent() {
      const template = SOC_THREAT_TEMPLATES[Math.floor(Math.random() * SOC_THREAT_TEMPLATES.length)];
      const region = SOC_REGIONS[Math.floor(Math.random() * SOC_REGIONS.length)];
      const now = new Date();

      this.stats.totalIntercepted += Math.floor(1 + Math.random() * 3);
      if (template.level === 'CRITICAL') {
        this.stats.highRiskBlocked += 1;
        playCyberSound('critical');
      } else {
        playCyberSound('ping');
      }

      this.stats.avgLatencyMs = Math.floor(11 + Math.random() * 8);

      const event = {
        id: 'EV-' + Math.floor(10000 + Math.random() * 90000),
        time: now.toLocaleTimeString(),
        region,
        ...template
      };

      this.listeners.forEach(fn => fn(event, this.stats));
    }
  }

  // --- Interactive Radar Visualizer ---
  class CyberRadar {
    constructor(canvasId) {
      this.canvas = document.getElementById(canvasId);
      if (!this.canvas) return;
      this.ctx = this.canvas.getContext('2d');
      this.angle = 0;
      this.blips = [];
      this.active = true;
      this._initBlips();
      this._animate = this._animate.bind(this);
      requestAnimationFrame(this._animate);
    }

    _initBlips() {
      for (let i = 0; i < 7; i++) {
        this.blips.push({
          r: 30 + Math.random() * 110,
          theta: Math.random() * Math.PI * 2,
          alpha: 0.2 + Math.random() * 0.8,
          danger: Math.random() > 0.6
        });
      }
    }

    addBlip(danger = true) {
      this.blips.push({
        r: 30 + Math.random() * 110,
        theta: this.angle,
        alpha: 1.0,
        danger
      });
      if (this.blips.length > 14) this.blips.shift();
    }

    _animate() {
      if (!this.active || !this.ctx) return;
      const ctx = this.ctx;
      const w = this.canvas.width;
      const h = this.canvas.height;
      const cx = w / 2;
      const cy = h / 2;
      const maxR = w / 2 - 12;

      ctx.clearRect(0, 0, w, h);

      // Radar background circles
      ctx.strokeStyle = 'rgba(34, 211, 238, 0.2)';
      ctx.lineWidth = 1;
      for (let r = 40; r <= maxR; r += 40) {
        ctx.beginPath();
        ctx.arc(cx, cy, r, 0, Math.PI * 2);
        ctx.stroke();
      }

      // Crosshairs
      ctx.beginPath();
      ctx.moveTo(cx - maxR, cy); ctx.lineTo(cx + maxR, cy);
      ctx.moveTo(cx, cy - maxR); ctx.lineTo(cx, cy + maxR);
      ctx.strokeStyle = 'rgba(34, 211, 238, 0.15)';
      ctx.stroke();

      // Sweeping beam
      this.angle = (this.angle + 0.025) % (Math.PI * 2);

      const grad = ctx.createRadialGradient(cx, cy, 0, cx, cy, maxR);
      grad.addColorStop(0, 'rgba(34, 211, 238, 0.25)');
      grad.addColorStop(1, 'transparent');

      ctx.save();
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, maxR, this.angle - 0.45, this.angle);
      ctx.closePath();
      ctx.fillStyle = grad;
      ctx.fill();
      ctx.restore();

      // Sweep lead line
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(cx + Math.cos(this.angle) * maxR, cy + Math.sin(this.angle) * maxR);
      ctx.strokeStyle = 'rgba(34, 211, 238, 0.8)';
      ctx.lineWidth = 2;
      ctx.stroke();

      // Draw blips
      for (const b of this.blips) {
        const bx = cx + Math.cos(b.theta) * b.r;
        const by = cy + Math.sin(b.theta) * b.r;
        ctx.beginPath();
        ctx.arc(bx, by, b.danger ? 4.5 : 3.5, 0, Math.PI * 2);
        ctx.fillStyle = b.danger ? `rgba(239, 68, 68, ${b.alpha})` : `rgba(34, 211, 238, ${b.alpha})`;
        ctx.shadowColor = b.danger ? '#EF4444' : '#22D3EE';
        ctx.shadowBlur = 8;
        ctx.fill();
        ctx.shadowBlur = 0;
        b.alpha = Math.max(0.15, b.alpha - 0.003);
      }

      requestAnimationFrame(this._animate);
    }
  }

  // --- Export Globally ---
  window.CyberEngine = {
    Auth,
    HistoryManager,
    analyzeScam,
    highlightScamTokens,
    generateComplaintDraft,
    analyzeUrl,
    analyzeApk,
    analyzePassword,
    TelemetryStream,
    CyberRadar,
    playCyberSound,
    toggleSound(val) {
      soundEnabled = typeof val === 'boolean' ? val : !soundEnabled;
      return soundEnabled;
    },
    isSoundEnabled() {
      return soundEnabled;
    }
  };

})(window);
