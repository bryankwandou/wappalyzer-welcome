import { en } from "./locales/en.js";
import { id } from "./locales/id.js";
import { analyzeTargetUrl, normalizeDomain, validateHostname } from "./data/techDatabase.js";

// State Management - 100% Public Access (No Login Required)
const state = {
  lang: localStorage.getItem("wappalyzer_lang") || (navigator.language.startsWith("id") ? "id" : "en"),
  theme: localStorage.getItem("wappalyzer_theme") || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"),
  currentScanDomain: "fti.uajy.ac.id",
  currentScanData: null,
  isExtensionActive: true,
  isScanning: false
};

// Monotonic scan coordinator to eliminate async race conditions
let activeScanId = 0;
let activeAbortController = null;

const dictionaries = { en, id };

// Escape untrusted dynamic text before interpolating into HTML templates (XSS prevention)
function escapeHtml(value) {
  if (value === null || value === undefined) return "";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Validate external URLs before assigning to href attributes
function safeHttpUrl(url) {
  if (!url || typeof url !== "string") return "#";
  return /^https?:\/\//i.test(url.trim()) ? url.trim() : "#";
}

// Helper to get nested translation value
function t(path) {
  const currentDict = dictionaries[state.lang] || dictionaries.en;
  const parts = path.split(".");
  let current = currentDict;
  for (const part of parts) {
    if (current && typeof current === "object" && part in current) {
      current = current[part];
    } else {
      return path;
    }
  }
  return current;
}

// Update DOM with translations
function applyTranslations() {
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const key = el.getAttribute("data-i18n");
    el.textContent = t(key);
  });

  const scanInput = document.getElementById("scan-domain-input");
  if (scanInput) scanInput.placeholder = t("scanner.inputPlaceholder");

  const currentLangText = document.getElementById("current-lang-text");
  if (currentLangText) {
    currentLangText.textContent = state.lang.toUpperCase() === "ID" ? "ID (Bahasa)" : "EN (English)";
  }
}

// Switch Language
function setLanguage(lang) {
  state.lang = lang;
  localStorage.setItem("wappalyzer_lang", lang);
  document.documentElement.lang = lang;
  applyTranslations();
  showToast(lang === "id" ? "Bahasa diubah ke Bahasa Indonesia" : "Language set to English");
}

// Theme handling
function applyTheme(theme) {
  state.theme = theme;
  localStorage.setItem("wappalyzer_theme", theme);
  document.documentElement.setAttribute("data-theme", theme);

  const sunIcon = document.getElementById("theme-icon-sun");
  const moonIcon = document.getElementById("theme-icon-moon");

  if (theme === "dark") {
    if (sunIcon) sunIcon.style.display = "none";
    if (moonIcon) moonIcon.style.display = "block";
  } else {
    if (sunIcon) sunIcon.style.display = "block";
    if (moonIcon) moonIcon.style.display = "none";
  }
}

function toggleTheme() {
  const nextTheme = state.theme === "dark" ? "light" : "dark";
  applyTheme(nextTheme);
  showToast(nextTheme === "dark" ? "Dark mode activated" : "Light mode activated");
}

// SVG Brand & Tech Icon Generator
function getTechIconSvg(iconName) {
  const svgs = {
    wordpress: `<svg viewBox="0 0 24 24" width="18" height="18"><circle cx="12" cy="12" r="10" fill="#21759B"/><path fill="#ffffff" d="M12 3.2c4.85 0 8.8 3.95 8.8 8.8 0 1.5-.38 2.9-1.05 4.13l-4.24-11.64c-.03-.09-.08-.18-.15-.24-.95-.7-2.1-.85-3.36-1.05zm-6.7 3.53c.63 1.51 1.84 4.91 2.47 6.67l-3.4-9.33c.29.85.61 1.76.93 2.66zm3.66 9.92l-2.5-7.25 3.84 11.16c-.48-.14-.95-.32-1.41-.54l.07-.01v-3.36zm3.04 5.38c-.66 0-1.3-.07-1.92-.2l3.43-9.95 3.52 9.65c-1.55.51-3.23.6-5.03.5zm6.79-4.17c.34-.69.59-1.44.73-2.22l-3.68-10.1c1.48 1.35 2.52 3.19 2.88 5.27.05.26.07.53.07.81 0 2.3-.87 4.4-2.31 5.99l2.31 6.25z"/></svg>`,
    "google-analytics": `<svg viewBox="0 0 24 24" width="18" height="18"><path fill="#F9AB00" d="M21 19.5h-3a1.5 1.5 0 0 1-1.5-1.5v-12a1.5 1.5 0 0 1 1.5-1.5h3A1.5 1.5 0 0 1 22.5 6v12a1.5 1.5 0 0 1-1.5 1.5z"/><path fill="#E37400" d="M13.5 19.5h-3a1.5 1.5 0 0 1-1.5-1.5v-7a1.5 1.5 0 0 1 1.5-1.5h3a1.5 1.5 0 0 1 1.5 1.5v7a1.5 1.5 0 0 1-1.5 1.5z"/><circle fill="#E37400" cx="4.5" cy="18" r="2.2"/></svg>`,
    gtm: `<svg viewBox="0 0 24 24" width="18" height="18"><path fill="#4285F4" d="M12 2L2 12l10 10 10-10L12 2zm0 4.2L17.8 12 12 17.8 6.2 12 12 6.2z"/><circle cx="12" cy="12" r="2.4" fill="#8AB4F8"/></svg>`,
    youtube: `<svg viewBox="0 0 24 24" width="18" height="18"><rect width="22" height="16" x="1" y="4" rx="4" fill="#FF0000"/><polygon points="9.5 8.5 15.5 12 9.5 15.5" fill="#FFFFFF"/></svg>`,
    "font-awesome": `<svg viewBox="0 0 24 24" width="18" height="18"><rect width="20" height="20" x="2" y="2" rx="3" fill="#339AF0"/><path fill="#FFFFFF" d="M15 14h-4v-1.8h3.4v-1.4H11V9.2h4.4V7.8H9.6v7.6H15z"/></svg>`,
    "google-maps": `<svg viewBox="0 0 24 24" width="18" height="18"><path fill="#EA4335" d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7z"/><circle fill="#4285F4" cx="12" cy="9" r="2.8"/></svg>`,
    elementor: `<svg viewBox="0 0 24 24" width="18" height="18"><circle cx="12" cy="12" r="10" fill="#1e1e1e"/><path fill="#FFFFFF" d="M8 8h2.2v8H8zm3.6 0h4.4v2h-4.4zm0 3h4.4v2h-4.4zm0 3h4.4v2h-4.4z"/></svg>`,
    select2: `<svg viewBox="0 0 24 24" width="18" height="18"><rect width="18" height="7" x="3" y="4" rx="2" fill="#E84D3D"/><rect width="18" height="7" x="3" y="13" rx="2" fill="#3498DB"/><circle cx="17" cy="7.5" r="1.3" fill="#FFFFFF"/><circle cx="7" cy="16.5" r="1.3" fill="#FFFFFF"/></svg>`,
    masonry: `<svg viewBox="0 0 24 24" width="18" height="18"><rect x="3" y="3" width="8" height="8" rx="1" fill="#1E88E5"/><rect x="13" y="3" width="8" height="12" rx="1" fill="#1E88E5"/><rect x="3" y="13" width="8" height="8" rx="1" fill="#1E88E5"/><rect x="13" y="17" width="8" height="4" rx="1" fill="#1E88E5"/></svg>`,
    "jquery-ui": `<svg viewBox="0 0 24 24" width="18" height="18"><path fill="#F39C12" d="M12 2L4 5.5v6.5c0 5 3.4 9.7 8 11 4.6-1.3 8-6 8-11V5.5L12 2z"/><path fill="#FFFFFF" d="M11 14.5l-3-3 1.2-1.2 1.8 1.8 4.8-4.8 1.2 1.2z"/></svg>`,
    "jquery-migrate": `<svg viewBox="0 0 24 24" width="18" height="18"><circle cx="12" cy="12" r="10" fill="#00A896"/><path fill="#FFFFFF" d="M12 5a7 7 0 0 0-7 7h2a5 5 0 0 1 5-5V5zm4.95 2.05l-1.41 1.41A5 5 0 0 1 17 12h2a7 7 0 0 0-2.05-4.95zM7 12H5a7 7 0 0 0 2.05 4.95l1.41-1.41A5 5 0 0 1 7 12zm5 5a5 5 0 0 1-5-5H5a7 7 0 0 0 7 7v-2z"/></svg>`,
    jquery: `<svg viewBox="0 0 24 24" width="18" height="18"><circle cx="12" cy="12" r="10" fill="#0769AD"/><path fill="#FFFFFF" d="M11 16.5c-2.5 0-4.5-2-4.5-4.5s2-4.5 4.5-4.5c1.6 0 3 .8 3.8 2.1l-1.7.9c-.4-.6-1.2-1-2.1-1-1.4 0-2.5 1.1-2.5 2.5s1.1 2.5 2.5 2.5c1.4 0 2.5-1.1 2.5-2.5 0-.4-.1-.8-.3-1.2l1.8-.9c.4.6.5 1.3.5 2.1 0 2.5-2 4.5-4.5 4.5z"/></svg>`,
    cloudflare: `<svg viewBox="0 0 24 24" width="18" height="18"><path fill="#F38020" d="M18.2 17H6.8a3.8 3.8 0 0 1-.4-7.58A5.5 5.5 0 0 1 17.1 8.6 3.5 3.5 0 0 1 18.2 17z"/></svg>`,
    vercel: `<svg viewBox="0 0 24 24" width="18" height="18"><polygon points="12 3 22 20 2 20" fill="#111827"/></svg>`,
    react: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#087EA4" stroke-width="1.6"><circle cx="12" cy="12" r="2.2" fill="#087EA4"/><ellipse cx="12" cy="12" rx="9" ry="3.6"/><ellipse cx="12" cy="12" rx="9" ry="3.6" transform="rotate(60 12 12)"/><ellipse cx="12" cy="12" rx="9" ry="3.6" transform="rotate(120 12 12)"/></svg>`,
    vue: `<svg viewBox="0 0 24 24" width="18" height="18"><polygon points="2 4 12 21 22 4 18 4 12 14.2 6 4" fill="#41B883"/><polygon points="6 4 12 14.2 18 4 14.5 4 12 8.2 9.5 4" fill="#35495E"/></svg>`,
    nextjs: `<svg viewBox="0 0 24 24" width="18" height="18"><circle cx="12" cy="12" r="10" fill="#111827"/><path stroke="#ffffff" stroke-width="1.8" d="M8.5 16V8l8.5 10.5M15.5 8v5.5"/></svg>`,
    nuxt: `<svg viewBox="0 0 24 24" width="18" height="18"><polygon points="2 19 10 5 18 19" fill="#00DC82"/><polygon points="10 19 15.5 9.5 21 19" fill="#00C16A"/></svg>`,
    tailwind: `<svg viewBox="0 0 24 24" width="18" height="18"><path fill="#06B6D4" d="M12 6c-2.67 0-4.33 1.33-5 4 1-1.33 2.17-1.83 3.5-1.5.76.19 1.31.74 1.91 1.35C13.39 10.84 14.53 12 17 12c2.67 0 4.33-1.33 5-4-1 1.33-2.17 1.83-3.5 1.5-.76-.19-1.31-.74-1.91-1.35C15.61 7.16 14.47 6 12 6zM7 12c-2.67 0-4.33 1.33-5 4 1-1.33 2.17-1.83 3.5-1.5.76.19 1.31.74 1.91 1.35C8.39 16.84 9.53 18 12 18c2.67 0 4.33-1.33 5-4-1 1.33-2.17 1.83-3.5 1.5-.76-.19-1.31-.74-1.91-1.35C10.61 13.16 9.47 12 7 12z"/></svg>`,
    php: `<svg viewBox="0 0 24 24" width="18" height="18"><ellipse cx="12" cy="12" rx="10.5" ry="6.5" fill="#777BB4"/><text x="12" y="14.6" text-anchor="middle" fill="#ffffff" font-size="7.5" font-weight="700" font-family="sans-serif">php</text></svg>`,
    nodejs: `<svg viewBox="0 0 24 24" width="18" height="18"><polygon points="12 2 21 7 21 17 12 22 3 17 3 7" fill="#339933"/><text x="12" y="14.5" text-anchor="middle" fill="#ffffff" font-size="7" font-weight="700" font-family="sans-serif">JS</text></svg>`,
    python: `<svg viewBox="0 0 24 24" width="18" height="18"><rect x="6" y="3" width="10" height="8" rx="3" fill="#3776AB"/><rect x="8" y="13" width="10" height="8" rx="3" fill="#FFD43B"/></svg>`,
    nginx: `<svg viewBox="0 0 24 24" width="18" height="18"><polygon points="12 2 21 7 21 17 12 22 3 17 3 7" fill="#009639"/><path stroke="#ffffff" stroke-width="2" fill="none" d="M8.5 16V8l7 8V8"/></svg>`,
    apache: `<svg viewBox="0 0 24 24" width="18" height="18"><path fill="#D22128" d="M18 3C13 5 8 11 6 19l2 2c2-4 6-8 11-11 1-2.5 1-5-1-7z"/></svg>`,
    litespeed: `<svg viewBox="0 0 24 24" width="18" height="18"><polygon points="13 2 5 13 11 13 10 22 19 10 13 10" fill="#2B6CB0"/></svg>`,
    drupal: `<svg viewBox="0 0 24 24" width="18" height="18"><path fill="#0678BE" d="M12 2.5C9.5 6 5 9.5 5 14a7 7 0 0 0 14 0c0-4.5-4.5-8-7-11.5z"/></svg>`,
    joomla: `<svg viewBox="0 0 24 24" width="18" height="18"><circle cx="8" cy="8" r="4" fill="#F44321"/><circle cx="16" cy="8" r="4" fill="#7AC143"/><circle cx="8" cy="16" r="4" fill="#5091CD"/><circle cx="16" cy="16" r="4" fill="#F9A541"/></svg>`,
    shopify: `<svg viewBox="0 0 24 24" width="18" height="18"><path fill="#95BF47" d="M18.5 6.5L17 20l-11-1.5L5.5 6.5h13z"/><path fill="#5E8E3E" d="M15 6.5a3 3 0 0 0-6 0" stroke="#5E8E3E" stroke-width="1.6" fill="none"/></svg>`,
    woocommerce: `<svg viewBox="0 0 24 24" width="18" height="18"><rect x="2" y="5" width="20" height="13" rx="3" fill="#7F54B3"/><text x="12" y="14" text-anchor="middle" fill="#ffffff" font-size="7" font-weight="700" font-family="sans-serif">WOO</text></svg>`,
    stripe: `<svg viewBox="0 0 24 24" width="18" height="18"><rect x="2" y="2" width="20" height="20" rx="4" fill="#635BFF"/><text x="12" y="16" text-anchor="middle" fill="#ffffff" font-size="13" font-weight="700" font-family="sans-serif">S</text></svg>`,
    meta: `<svg viewBox="0 0 24 24" width="18" height="18"><circle cx="12" cy="12" r="10" fill="#1877F2"/><path fill="#ffffff" d="M13.5 18v-5h1.7l.3-2h-2V9.8c0-.6.2-1 1-1h1.1V7h-1.8c-1.8 0-2.8 1-2.8 2.7V11H9.5v2H11v5h2.5z"/></svg>`,
    recaptcha: `<svg viewBox="0 0 24 24" width="18" height="18"><path fill="#1C3AA9" d="M12 3a9 9 0 0 1 8.5 6h-3.2A6 6 0 0 0 12 6V3z"/><path fill="#4285F4" d="M12 21a9 9 0 0 1-8.5-6h3.2a6 6 0 0 0 5.3 3v3z"/></svg>`,
    network: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M3.6 9h16.8M3.6 15h16.8M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg>`,
    code: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>`,
    server: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line></svg>`,
    cloud: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"></path></svg>`,
    palette: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="13.5" cy="6.5" r=".5"></circle><circle cx="17.5" cy="10.5" r=".5"></circle><circle cx="8.5" cy="7.5" r=".5"></circle><circle cx="6.5" cy="12.5" r=".5"></circle><path d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10c.926 0 1.648-.746 1.648-1.688 0-.437-.18-.835-.437-1.125-.29-.289-.438-.652-.438-1.125a1.64 1.64 0 0 1 1.668-1.668h1.996c3.051 0 5.555-2.503 5.555-5.554C21.965 6.012 17.461 2 12 2z"></path></svg>`,
    shield: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>`,
    "shopping-bag": `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 2L3 6v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6l-3-4z"></path><line x1="3" y1="6" x2="21" y2="6"></line><path d="M16 10a4 4 0 0 1-8 0"></path></svg>`,
    "credit-card": `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="1" y="4" width="22" height="16" rx="2" ry="2"></rect><line x1="1" y1="10" x2="23" y2="10"></line></svg>`,
    microsoft: `<svg viewBox="0 0 24 24" width="18" height="18"><rect x="2" y="2" width="9.5" height="9.5" fill="#F25022"/><rect x="12.5" y="2" width="9.5" height="9.5" fill="#7FBA00"/><rect x="2" y="12.5" width="9.5" height="9.5" fill="#00A4EF"/><rect x="12.5" y="12.5" width="9.5" height="9.5" fill="#FFB900"/></svg>`,
    bootstrap: `<svg viewBox="0 0 24 24" width="18" height="18"><rect x="2" y="2" width="20" height="20" rx="4" fill="#7952B3"/><path fill="#ffffff" d="M8.5 6.5h4.2c1.7 0 2.8.9 2.8 2.2 0 1-.6 1.7-1.5 1.9 1.2.3 1.9 1.1 1.9 2.2 0 1.5-1.2 2.5-3.1 2.5H8.5V6.5zm2.1 3.5h1.8c.6 0 1-.3 1-.8s-.4-.8-1-.8h-1.8V10zm0 3.7h2c.7 0 1.1-.3 1.1-.9s-.4-.9-1.1-.9h-2v1.8z"/></svg>`,
    f5: `<svg viewBox="0 0 24 24" width="18" height="18"><circle cx="12" cy="12" r="10" fill="#E2231A"/><path fill="#ffffff" d="M8 7h8v2H10v3h5v2h-5v3H8V7z"/></svg>`
  };
  return svgs[iconName] || svgs.code;
}

function syncActiveChip(domain) {
  const norm = normalizeDomain(domain);
  document.querySelectorAll(".quick-chip").forEach((chip) => {
    const chipDomain = normalizeDomain(chip.getAttribute("data-domain") || "");
    chip.classList.toggle("active", chipDomain === norm);
  });
}

function renderLoadingState(targetDomain) {
  const container = document.getElementById("popup-columns-container");
  if (!container) return;
  container.innerHTML = `
    <div style="grid-column: 1 / -1; padding: 48px 24px; text-align: center;">
      <div class="spinner" style="border-color: rgba(70,8,173,0.2); border-top-color: #4608ad; width: 28px; height: 28px; margin: 0 auto 14px;"></div>
      <div style="font-size: 14px; font-weight: 600; color: #1e1160;">
        Memindai header HTTP, DNS, dan DOM untuk ${escapeHtml(targetDomain)}...
      </div>
    </div>
  `;
}

function renderPausedState() {
  const container = document.getElementById("popup-columns-container");
  if (!container) return;
  container.innerHTML = `
    <div style="grid-column: 1 / -1; padding: 48px 24px; text-align: center;">
      <div style="font-size: 15px; font-weight: 700; color: #1e1160; margin-bottom: 6px;">
        Deteksi Ekstensi Dijeda
      </div>
      <div style="font-size: 13px; color: #6b7280; max-width: 360px; margin: 0 auto;">
        Aktifkan kembali sakelar di pojok kanan atas kartu Wappalyzer untuk melanjutkan pemindaian.
      </div>
    </div>
  `;
}

// Execute Live Scan with Abort & Race-Condition Protection
async function runTechnologyScan(targetDomain, { fresh = false } = {}) {
  if (!state.isExtensionActive) {
    renderPausedState();
    showToast("Deteksi sedang dijeda. Aktifkan sakelar ekstensi terlebih dahulu.");
    return;
  }

  const domainInput = document.getElementById("scan-domain-input");
  const rawTarget = targetDomain !== undefined ? targetDomain : (domainInput ? domainInput.value.trim() : "");
  if (!rawTarget) return;

  // Cancel any in-flight scan immediately
  if (activeAbortController) {
    activeAbortController.abort();
  }
  activeAbortController = new AbortController();
  const scanId = ++activeScanId;

  const submitBtn = document.getElementById("scan-submit-btn");
  const btnText = document.getElementById("scan-btn-text");
  const spinner = document.getElementById("scan-spinner");

  state.isScanning = true;
  if (submitBtn) submitBtn.disabled = true;
  if (btnText) btnText.style.display = "none";
  if (spinner) spinner.style.display = "inline-block";

  syncActiveChip(rawTarget);
  renderLoadingState(normalizeDomain(rawTarget) || rawTarget);

  try {
    const analysis = await analyzeTargetUrl(rawTarget, {
      signal: activeAbortController.signal,
      fresh
    });

    // Drop stale out-of-order responses
    if (scanId !== activeScanId) return;

    state.currentScanDomain = analysis.domain;
    state.currentScanData = analysis;

    renderScanResults();
    if (analysis.isInvalid) {
      showToast(analysis.ghostReason || "Format domain tidak valid");
    } else if (analysis.isGhost) {
      showToast(`Host tidak ditemukan: ${analysis.domain}`);
    } else {
      showToast(`${analysis.totalCount} technologies detected for ${analysis.domain}`);
    }
  } catch (err) {
    if (err && err.name === "AbortError") {
      return;
    }
    if (scanId !== activeScanId) return;

    const cleaned = normalizeDomain(rawTarget) || rawTarget;
    state.currentScanDomain = cleaned;
    state.currentScanData = {
      domain: cleaned,
      httpStatus: 0,
      totalCount: 0,
      isGhost: true,
      isInvalid: false,
      ghostReason: "Gagal menghubungi layanan pemindai jaringan. Periksa koneksi lalu coba lagi.",
      leftColumn: [],
      rightColumn: [],
      algorithmEvidence: [
        {
          id: "EVID-L1-NETERR",
          layer: "L1_NETWORK",
          tech: "Network Request Error",
          rule: "Client Fetch Failure",
          detail: err && err.message ? err.message : "Network error",
          confidence: "100%"
        }
      ]
    };
    renderScanResults();
    showToast(`Pemindaian gagal untuk ${cleaned}`);
  } finally {
    if (scanId === activeScanId) {
      state.isScanning = false;
      if (submitBtn) submitBtn.disabled = false;
      if (btnText) btnText.style.display = "inline";
      if (spinner) spinner.style.display = "none";
    }
  }
}

// Render Exact 2-Column Wappalyzer Popup Layout
function renderScanResults() {
  const container = document.getElementById("popup-columns-container");
  const moreInfoPanel = document.getElementById("popup-more-info-panel");
  const moreInfoDomain = document.getElementById("more-info-domain");
  const data = state.currentScanData;

  if (!data) return;

  if (moreInfoDomain) {
    moreInfoDomain.textContent = data.finalUrl || `https://${data.domain}`;
  }

  if (moreInfoPanel) {
    const isGhost = Boolean(data.isGhost);
    const isInvalid = Boolean(data.isInvalid);
    const isPartial = Boolean(data.partialScan);

    let statusHtml = `<span style="color:#10b981; font-weight:700;">HTTP ${escapeHtml(data.httpStatus || 200)} OK</span>`;
    if (isInvalid) {
      statusHtml = `<span style="color:#d97706; font-weight:700;">Input Ditolak / Diblokir</span>`;
    } else if (isGhost) {
      statusHtml = `<span style="color:#ef4444; font-weight:700;">Host Unreachable / NXDOMAIN</span>`;
    } else if (isPartial && data.httpStatus > 0) {
      statusHtml = `<span style="color:#d97706; font-weight:700;">HTTP ${escapeHtml(data.httpStatus)} (WAF / Partial)</span>`;
    } else if (isPartial) {
      statusHtml = `<span style="color:#2563eb; font-weight:700;">DNS Active (Partial Wire)</span>`;
    }

    const badgeBg = isGhost ? "#fee2e2" : isPartial ? "#fef3c7" : "#dcffd6";
    const badgeColor = isGhost ? "#b91c1c" : isPartial ? "#92400e" : "#10b981";

    const evidenceRows = (data.algorithmEvidence || []).map((ev) => `
      <tr style="border-bottom:1px solid rgba(0,0,0,0.06);">
        <td style="padding:6px 8px; font-family:monospace; font-weight:600; color:#4608ad;">${escapeHtml(ev.id)}</td>
        <td style="padding:6px 8px;"><span style="background:${isGhost ? "#fee2e2" : "#f0ebf9"}; color:${isGhost ? "#b91c1c" : "#4608ad"}; padding:2px 6px; border-radius:4px; font-size:11px; font-weight:600;">${escapeHtml(ev.layer)}</span></td>
        <td style="padding:6px 8px; font-weight:600;">${escapeHtml(ev.tech)}</td>
        <td style="padding:6px 8px; font-family:monospace; font-size:11px; color:#56516d;">${escapeHtml(ev.rule)}</td>
        <td style="padding:6px 8px; font-size:11px; color:#374151; word-break:break-word;">${escapeHtml(ev.detail || "-")}</td>
        <td style="padding:6px 8px; color:${isGhost ? "#ef4444" : "#10b981"}; font-weight:700;">${escapeHtml(ev.confidence)}</td>
      </tr>
    `).join("");

    const targetHref = safeHttpUrl(data.finalUrl || `https://${data.domain}`);
    const scanNoteHtml = data.scanNote
      ? `<div style="margin-bottom:12px; padding:8px 10px; border-radius:6px; background:#fffbeb; border:1px solid #fde68a; color:#92400e; font-size:12px;">${escapeHtml(data.scanNote)}</div>`
      : "";

    const dnsSummary = data.dns && data.dns.ip
      ? `<div><strong>DNS IP:</strong> <span>${escapeHtml(data.dns.ip)}</span></div>`
      : "";

    moreInfoPanel.innerHTML = `
      <div style="font-size:13px; line-height:1.7; color:#181528;">
        <div style="display:flex; justify-content:space-between; flex-wrap:wrap; gap:8px; margin-bottom:14px; padding-bottom:12px; border-bottom:1px solid #e5e0f2;">
          <div><strong>Target:</strong> <a href="${escapeHtml(targetHref)}" target="_blank" rel="noopener noreferrer" style="color:#2196f3; font-weight:600;">${escapeHtml(data.finalUrl || `https://${data.domain}`)}</a></div>
          <div><strong>Status:</strong> ${statusHtml}</div>
          <div><strong>Server:</strong> <span>${escapeHtml(data.serverLocation || "Global Edge")}</span></div>
          ${dnsSummary}
          <div><strong>Response Time:</strong> <span>${data.responseTimeMs ? `${escapeHtml(data.responseTimeMs)} ms` : "N/A"}</span></div>
          <div><strong>Protocol:</strong> <span>${escapeHtml(data.tlsVersion || "HTTPS / TLS")}</span></div>
        </div>
        ${scanNoteHtml}
        <div style="margin-top:10px;">
          <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:8px;">
            <strong style="color:#1e1160; font-size:12px; text-transform:uppercase; letter-spacing:0.04em;">Technology Evidence Details</strong>
            <span style="font-size:11px; color:${badgeColor}; background:${badgeBg}; padding:2px 8px; border-radius:9999px; font-weight:700;">${escapeHtml(data.totalCount || 0)} Detected</span>
          </div>
          <div style="overflow-x:auto; border:1px solid #e5e0f2; border-radius:8px; background:#ffffff;">
            <table style="width:100%; border-collapse:collapse; font-size:12px; text-align:left;">
              <thead style="background:#f8f7fc; border-bottom:1px solid #e5e0f2;">
                <tr>
                  <th style="padding:6px 8px;">Evidence ID</th>
                  <th style="padding:6px 8px;">Layer</th>
                  <th style="padding:6px 8px;">Technology</th>
                  <th style="padding:6px 8px;">Match Rule</th>
                  <th style="padding:6px 8px;">Wire / DOM Detail</th>
                  <th style="padding:6px 8px;">Confidence</th>
                </tr>
              </thead>
              <tbody>
                ${evidenceRows}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;
  }

  if (!container) return;
  container.innerHTML = "";

  if (data.isGhost || data.totalCount === 0) {
    const titleText = data.isInvalid
      ? "Input Domain Tidak Valid atau Diblokir"
      : data.isGhost
        ? "Host Tidak Ditemukan (NXDOMAIN / 404)"
        : "Tidak Ada Tanda Tangan Teknologi Terdeteksi";
    const descText = data.ghostReason || data.scanNote || `Target ${data.domain} tidak mengembalikan sinyal teknologi yang dapat diverifikasi.`;

    container.innerHTML = `
      <div style="grid-column: 1 / -1; padding: 48px 24px; text-align: center;">
        <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="${data.isInvalid ? "#d97706" : "#ef4444"}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-bottom: 12px; display: inline-block;">
          <circle cx="12" cy="12" r="10"></circle>
          <line x1="12" y1="8" x2="12" y2="12"></line>
          <line x1="12" y1="16" x2="12.01" y2="16"></line>
        </svg>
        <div style="font-size: 15px; font-weight: 700; color: #1e1160; margin-bottom: 6px;">
          ${escapeHtml(titleText)}
        </div>
        <div style="font-size: 13px; color: #6b7280; max-width: 420px; margin: 0 auto; line-height: 1.5;">
          ${escapeHtml(descText)}
        </div>
      </div>
    `;
    return;
  }

  const leftCol = document.createElement("div");
  leftCol.className = "popup-column left-column";

  const rightCol = document.createElement("div");
  rightCol.className = "popup-column right-column";

  data.leftColumn.forEach((group) => {
    leftCol.appendChild(createCategoryGroupEl(group));
  });

  data.rightColumn.forEach((group) => {
    rightCol.appendChild(createCategoryGroupEl(group));
  });

  container.appendChild(leftCol);
  container.appendChild(rightCol);
}

function createCategoryGroupEl(group) {
  const groupEl = document.createElement("div");
  groupEl.className = "category-group";

  const titleEl = document.createElement("div");
  titleEl.className = "category-title";
  titleEl.textContent = group.category;
  groupEl.appendChild(titleEl);

  const listEl = document.createElement("div");
  listEl.className = "tech-items-list";

  group.items.forEach((item) => {
    const row = document.createElement("div");
    row.className = "tech-item-row";

    const iconSpan = document.createElement("span");
    iconSpan.className = "tech-brand-icon";
    iconSpan.innerHTML = getTechIconSvg(item.icon);

    const link = document.createElement("a");
    link.className = "tech-name-link";
    link.href = safeHttpUrl(item.url);
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = item.name;

    row.appendChild(iconSpan);
    row.appendChild(link);

    if (item.version) {
      const ver = document.createElement("span");
      ver.className = "tech-version-tag";
      ver.textContent = item.version;
      row.appendChild(ver);
    }

    listEl.appendChild(row);
  });

  groupEl.appendChild(listEl);
  return groupEl;
}

// Export Stack Data (JSON copy & download)
function exportTechStack() {
  if (!state.currentScanData) return;

  const payload = {
    domain: state.currentScanDomain,
    url: state.currentScanData.finalUrl || `https://${state.currentScanDomain}`,
    httpStatus: state.currentScanData.httpStatus ?? null,
    responseTimeMs: state.currentScanData.responseTimeMs ?? null,
    totalCount: state.currentScanData.totalCount,
    leftColumn: state.currentScanData.leftColumn,
    rightColumn: state.currentScanData.rightColumn,
    evidence: state.currentScanData.algorithmEvidence || []
  };

  const jsonString = JSON.stringify(payload, null, 2);

  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(jsonString).catch(() => { });
  }

  const blob = new Blob([jsonString], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `wappalyzer-${state.currentScanDomain.replace(/[^a-z0-9.-]/gi, "_")}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  showToast(`Exported ${state.currentScanData.totalCount} technologies for ${state.currentScanDomain}`);
}

// Toast Notifications (XSS-safe text rendering)
function showToast(message) {
  const container = document.getElementById("toast-container");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = "toast";

  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("width", "18");
  svg.setAttribute("height", "18");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2");
  const poly = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
  poly.setAttribute("points", "20 6 9 17 4 12");
  svg.appendChild(poly);

  const textSpan = document.createElement("span");
  textSpan.textContent = String(message);

  toast.appendChild(svg);
  toast.appendChild(textSpan);
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateX(100%)";
    toast.style.transition = "all 0.3s ease";
    setTimeout(() => toast.remove(), 300);
  }, 3200);
}

// Modal System
function openModal(title, contentHtml) {
  const modal = document.getElementById("generic-modal");
  const titleEl = document.getElementById("modal-title-text");
  const bodyEl = document.getElementById("modal-body-content");

  if (!modal || !titleEl || !bodyEl) return;

  titleEl.textContent = title;
  bodyEl.innerHTML = contentHtml;
  modal.classList.add("active");
  modal.setAttribute("aria-hidden", "false");
}

function closeModal() {
  const modal = document.getElementById("generic-modal");
  if (!modal) return;
  modal.classList.remove("active");
  modal.setAttribute("aria-hidden", "true");
}

// Initialize Application - 100% Free Public Mode
document.addEventListener("DOMContentLoaded", () => {
  applyTheme(state.theme);
  applyTranslations();

  const scanInput = document.getElementById("scan-domain-input");
  const initialDomain = (scanInput && scanInput.value.trim()) || state.currentScanDomain;
  if (scanInput) scanInput.value = initialDomain;

  // Trigger genuine live network scan on initial load
  runTechnologyScan(initialDomain);

  // Popup Switch Toggle (actually pauses/resumes scanning)
  const popupSwitch = document.getElementById("popup-switch");
  const toggleExtensionState = () => {
    state.isExtensionActive = !state.isExtensionActive;
    popupSwitch.classList.toggle("active", state.isExtensionActive);
    if (state.isExtensionActive) {
      showToast("Extension detection active");
      runTechnologyScan(scanInput ? scanInput.value.trim() : state.currentScanDomain);
    } else {
      if (activeAbortController) activeAbortController.abort();
      renderPausedState();
      showToast("Extension detection paused");
    }
  };
  if (popupSwitch) {
    popupSwitch.addEventListener("click", toggleExtensionState);
    popupSwitch.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        toggleExtensionState();
      }
    });
  }

  // Popup Gear Settings Button (force-refresh uncached live scan)
  const gearBtn = document.getElementById("popup-gear-btn");
  if (gearBtn) {
    gearBtn.addEventListener("click", () => {
      const target = (scanInput && scanInput.value.trim()) || state.currentScanDomain;
      showToast(`Memindai ulang ${normalizeDomain(target) || target} (bypass cache)...`);
      runTechnologyScan(target, { fresh: true });
    });
  }

  // Popup Tab Switching (TECHNOLOGIES / MORE INFO)
  const tabTech = document.getElementById("tab-technologies");
  const tabMore = document.getElementById("tab-more-info");
  const popupGrid = document.getElementById("popup-columns-container");
  const moreInfoPanel = document.getElementById("popup-more-info-panel");

  if (tabTech && tabMore && popupGrid && moreInfoPanel) {
    tabTech.addEventListener("click", () => {
      tabTech.classList.add("active");
      tabMore.classList.remove("active");
      popupGrid.style.display = "grid";
      moreInfoPanel.style.display = "none";
    });

    tabMore.addEventListener("click", () => {
      tabMore.classList.add("active");
      tabTech.classList.remove("active");
      popupGrid.style.display = "none";
      moreInfoPanel.style.display = "block";
    });
  }

  // Export Button Click
  const exportBtn = document.getElementById("popup-export-btn");
  if (exportBtn) {
    exportBtn.addEventListener("click", exportTechStack);
  }

  // Theme Toggle Event
  const themeBtn = document.getElementById("theme-toggle-btn");
  if (themeBtn) {
    themeBtn.addEventListener("click", toggleTheme);
  }

  // Language Toggle Event
  const langBtn = document.getElementById("lang-toggle-btn");
  if (langBtn) {
    langBtn.addEventListener("click", () => {
      setLanguage(state.lang === "en" ? "id" : "en");
    });
  }

  // Scan Form Submit
  const scanForm = document.getElementById("tech-scan-form");
  let inputDebounce = null;
  if (scanForm) {
    scanForm.addEventListener("submit", (e) => {
      e.preventDefault();
      clearTimeout(inputDebounce);
      runTechnologyScan();
    });
  }

  // Smart auto-scan on input: only triggers after 600ms pause AND when input is a syntactically valid FQDN
  if (scanInput) {
    scanInput.addEventListener("input", (e) => {
      clearTimeout(inputDebounce);
      const val = e.target.value.trim();
      const normalized = normalizeDomain(val);
      if (normalized && normalized !== state.currentScanDomain && validateHostname(normalized).valid) {
        inputDebounce = setTimeout(() => {
          runTechnologyScan(normalized);
        }, 600);
      }
    });
  }

  // Quick Target Chips
  document.querySelectorAll(".quick-chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      clearTimeout(inputDebounce);
      const domain = chip.getAttribute("data-domain");
      if (scanInput) scanInput.value = domain;
      runTechnologyScan(domain);
    });
  });

  // Search Modal Trigger
  const searchBtn = document.getElementById("search-modal-trigger");
  if (searchBtn) {
    searchBtn.addEventListener("click", () => {
      openModal(
        t("modal.searchTitle"),
        `
        <form id="modal-search-form" style="display:flex; gap:8px; margin-bottom:16px;">
          <input type="text" id="modal-search-field" class="scan-input" placeholder="${escapeHtml(t("modal.searchPlaceholder"))}" autofocus>
          <button type="submit" class="scan-submit-btn">Scan</button>
        </form>
        <div style="font-size:13px; color:var(--color-on-surface-variant); line-height: 1.6;">
          <div style="margin-bottom:8px; font-weight:600;">Popular Categories:</div>
          <ul style="list-style:inside disc; display:grid; grid-template-columns:1fr 1fr; gap:6px;">
            <li>Web Frameworks (Laravel, Next.js, Nuxt.js)</li>
            <li>Programming Languages (PHP, TypeScript)</li>
            <li>Security & WAF (F5 BIG-IP, Cloudflare)</li>
            <li>Content Management (WordPress, Ghost)</li>
            <li>CDN & Hosting (Vercel, Fastly)</li>
            <li>Analytics (Google Analytics 4, Clarity)</li>
          </ul>
        </div>
        `
      );
      const modalForm = document.getElementById("modal-search-form");
      const modalField = document.getElementById("modal-search-field");
      if (modalForm && modalField) {
        modalField.focus();
        modalForm.addEventListener("submit", (e) => {
          e.preventDefault();
          const query = modalField.value.trim();
          if (query) {
            if (scanInput) scanInput.value = query;
            closeModal();
            runTechnologyScan(query);
          }
        });
      }
    });
  }

  // Terms Modal Trigger
  const termsBtn = document.getElementById("terms-modal-trigger");
  if (termsBtn) {
    termsBtn.addEventListener("click", () => {
      openModal(
        t("modal.termsTitle"),
        `<p style="font-size:14px; line-height:1.6; color:var(--color-on-surface-variant);">${escapeHtml(t("modal.termsBody"))}</p>`
      );
    });
  }

  // Privacy Modal Trigger
  const privacyBtn = document.getElementById("privacy-modal-trigger");
  if (privacyBtn) {
    privacyBtn.addEventListener("click", () => {
      openModal(
        t("modal.privacyTitle"),
        `<p style="font-size:14px; line-height:1.6; color:var(--color-on-surface-variant);">${escapeHtml(t("modal.privacyBody"))}</p>`
      );
    });
  }

  // Close Modal Events
  const modalCloseBtn = document.getElementById("modal-close-btn");
  if (modalCloseBtn) {
    modalCloseBtn.addEventListener("click", closeModal);
  }

  const modalOverlay = document.getElementById("generic-modal");
  if (modalOverlay) {
    modalOverlay.addEventListener("click", (e) => {
      if (e.target === modalOverlay) closeModal();
    });
  }

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeModal();
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      if (searchBtn) searchBtn.click();
    }
  });
});
