import { en } from "./locales/en.js";
import { id } from "./locales/id.js";
import { analyzeTargetUrl, normalizeDomain, validateHostname } from "./data/techDatabase.js";

// Application State (100% Public Access)
const state = {
  lang: localStorage.getItem("wappalyzer_lang") || (navigator.language.startsWith("id") ? "id" : "en"),
  theme: localStorage.getItem("wappalyzer_theme") || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"),
  currentScanDomain: "fti.uajy.ac.id",
  currentScanData: null,
  activeTab: "technologies",
  activeEvidenceLayer: "ALL",
  techSearchQuery: "",
  highlightedEvidenceId: null,
  isExtensionActive: true,
  isScanning: false
};

// Monotonic scan coordinator to eliminate async race conditions
let activeScanId = 0;
let activeAbortController = null;
let pipelineAnimTimer = null;

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

function formatBytes(bytes) {
  if (typeof bytes !== "number" || bytes <= 0) return "--";
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(1)} KB`;
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

function setLanguage(lang) {
  state.lang = lang;
  localStorage.setItem("wappalyzer_lang", lang);
  document.documentElement.lang = lang;
  applyTranslations();
  showToast(lang === "id" ? "Bahasa diubah ke Bahasa Indonesia" : "Language set to English");
}

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
    shopify: `<svg viewBox="0 0 24 24" width="18" height="18"><path fill="#95BF47" d="M18.5 6.5L17 20l-11-1.5L5.5 6.5h13z"/><path fill="none" stroke="#5E8E3E" stroke-width="1.6" d="M15 6.5a3 3 0 0 0-6 0"/></svg>`,
    woocommerce: `<svg viewBox="0 0 24 24" width="18" height="18"><rect x="2" y="5" width="20" height="13" rx="3" fill="#7F54B3"/><text x="12" y="14" text-anchor="middle" fill="#ffffff" font-size="7" font-weight="700" font-family="sans-serif">WOO</text></svg>`,
    stripe: `<svg viewBox="0 0 24 24" width="18" height="18"><rect x="2" y="2" width="20" height="20" rx="4" fill="#635BFF"/><text x="12" y="16" text-anchor="middle" fill="#ffffff" font-size="13" font-weight="700" font-family="sans-serif">S</text></svg>`,
    meta: `<svg viewBox="0 0 24 24" width="18" height="18"><circle cx="12" cy="12" r="10" fill="#1877F2"/><path fill="#ffffff" d="M13.5 18v-5h1.7l.3-2h-2V9.8c0-.6.2-1 1-1h1.1V7h-1.8c-1.8 0-2.8 1-2.8 2.7V11H9.5v2H11v5h2.5z"/></svg>`,
    recaptcha: `<svg viewBox="0 0 24 24" width="18" height="18"><path fill="#1C3AA9" d="M12 3a9 9 0 0 1 8.5 6h-3.2A6 6 0 0 0 12 6V3z"/><path fill="#4285F4" d="M12 21a9 9 0 0 1-8.5-6h3.2a6 6 0 0 0 5.3 3v3z"/></svg>`,
    network: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M3.6 9h16.8M3.6 15h16.8M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg>`,
    code: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#4b5563" stroke-width="2"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>`,
    server: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#4b5563" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line></svg>`,
    cloud: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="2"><path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"></path></svg>`,
    palette: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#4608ad" stroke-width="2"><circle cx="13.5" cy="6.5" r=".5"></circle><circle cx="17.5" cy="10.5" r=".5"></circle><circle cx="8.5" cy="7.5" r=".5"></circle><circle cx="6.5" cy="12.5" r=".5"></circle><path d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10c.926 0 1.648-.746 1.648-1.688 0-.437-.18-.835-.437-1.125-.29-.289-.438-.652-.438-1.125a1.64 1.64 0 0 1 1.668-1.668h1.996c3.051 0 5.555-2.503 5.555-5.554C21.965 6.012 17.461 2 12 2z"></path></svg>`,
    shield: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>`,
    "shopping-bag": `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="2"><path d="M6 2L3 6v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6l-3-4z"></path><line x1="3" y1="6" x2="21" y2="6"></line><path d="M16 10a4 4 0 0 1-8 0"></path></svg>`,
    "credit-card": `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#4608ad" stroke-width="2"><rect x="1" y="4" width="22" height="16" rx="2" ry="2"></rect><line x1="1" y1="10" x2="23" y2="10"></line></svg>`,
    microsoft: `<svg viewBox="0 0 24 24" width="18" height="18"><rect x="2" y="2" width="9.5" height="9.5" fill="#F25022"/><rect x="12.5" y="2" width="9.5" height="9.5" fill="#7FBA00"/><rect x="2" y="12.5" width="9.5" height="9.5" fill="#00A4EF"/><rect x="12.5" y="12.5" width="9.5" height="9.5" fill="#FFB900"/></svg>`,
    bootstrap: `<svg viewBox="0 0 24 24" width="18" height="18"><rect x="2" y="2" width="20" height="20" rx="4" fill="#7952B3"/><path fill="#ffffff" d="M8.5 6.5h4.2c1.7 0 2.8.9 2.8 2.2 0 1-.6 1.7-1.5 1.9 1.2.3 1.9 1.1 1.9 2.2 0 1.5-1.2 2.5-3.1 2.5H8.5V6.5zm2.1 3.5h1.8c.6 0 1-.3 1-.8s-.4-.8-1-.8h-1.8V10zm0 3.7h2c.7 0 1.1-.3 1.1-.9s-.4-.9-1.1-.9h-2v1.8z"/></svg>`,
    f5: `<svg viewBox="0 0 24 24" width="18" height="18"><circle cx="12" cy="12" r="10" fill="#E2231A"/><path fill="#ffffff" d="M8 7h8v2H10v3h5v2h-5v3H8V7z"/></svg>`
  };
  return svgs[iconName] || svgs.code;
}

// ==========================================================================
// GPU-ACCELERATED HERO CONSTELLATION MOTION CANVAS
// ==========================================================================
function initHeroMotionCanvas() {
  const canvas = document.getElementById("hero-motion-canvas");
  if (!canvas) return;
  if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  let width = 0;
  let height = 0;
  let rafId = null;
  let nodes = [];

  function resize() {
    const rect = canvas.parentElement.getBoundingClientRect();
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    width = rect.width;
    height = rect.height;
    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    const count = Math.min(34, Math.max(16, Math.floor(width / 38)));
    nodes = Array.from({ length: count }, () => ({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.42,
      vy: (Math.random() - 0.5) * 0.32,
      r: 1.4 + Math.random() * 1.8
    }));
  }

  function step() {
    if (document.hidden) {
      rafId = requestAnimationFrame(step);
      return;
    }

    ctx.clearRect(0, 0, width, height);

    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      n.x += n.vx;
      n.y += n.vy;
      if (n.x < 0 || n.x > width) n.vx *= -1;
      if (n.y < 0 || n.y > height) n.vy *= -1;

      for (let j = i + 1; j < nodes.length; j++) {
        const m = nodes[j];
        const dx = n.x - m.x;
        const dy = n.y - m.y;
        const dist = Math.hypot(dx, dy);
        if (dist < 135) {
          const alpha = (1 - dist / 135) * 0.24;
          ctx.strokeStyle = `rgba(196, 181, 253, ${alpha.toFixed(3)})`;
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(n.x, n.y);
          ctx.lineTo(m.x, m.y);
          ctx.stroke();
        }
      }

      ctx.fillStyle = "rgba(255, 255, 255, 0.55)";
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
      ctx.fill();
    }

    rafId = requestAnimationFrame(step);
  }

  resize();
  window.addEventListener("resize", resize, { passive: true });
  rafId = requestAnimationFrame(step);

  window.addEventListener("beforeunload", () => {
    if (rafId) cancelAnimationFrame(rafId);
  });
}

// Scroll Reveal Observer & Header Elevation
function initScrollChoreography() {
  const header = document.querySelector(".site-header");
  const updateHeader = () => {
    if (header) header.classList.toggle("scrolled", window.scrollY > 12);
  };
  window.addEventListener("scroll", updateHeader, { passive: true });
  updateHeader();

  const targets = document.querySelectorAll(".reveal-on-scroll");
  if (!("IntersectionObserver" in window)) {
    targets.forEach((el) => el.classList.add("is-visible"));
    return;
  }

  const io = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          io.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.12 }
  );
  targets.forEach((el) => io.observe(el));
}

// Smooth Count-Up Metric Animator
function animateMetric(el, targetNumber, suffix = "") {
  if (!el) return;
  if (typeof targetNumber !== "number" || Number.isNaN(targetNumber)) {
    el.textContent = "--";
    return;
  }
  if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    el.textContent = `${targetNumber}${suffix}`;
    return;
  }

  const startTime = performance.now();
  const duration = 380;
  function tick(now) {
    const progress = Math.min(1, (now - startTime) / duration);
    const eased = 1 - Math.pow(1 - progress, 3);
    const current = Math.round(targetNumber * eased);
    el.textContent = `${current}${suffix}`;
    if (progress < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

// ==========================================================================
// 5-LAYER PIPELINE & TELEMETRY UPDATERS
// ==========================================================================
function setPipelineScanning(isScanning) {
  const track = document.getElementById("scan-pipeline-bar");
  const pill = document.getElementById("engine-status-pill");
  const pillLabel = document.getElementById("engine-status-label");
  const gearBtn = document.getElementById("popup-gear-btn");

  clearInterval(pipelineAnimTimer);
  if (!track) return;

  const stages = Array.from(track.querySelectorAll(".pipeline-stage"));
  if (isScanning) {
    track.classList.add("is-scanning");
    if (pill) {
      pill.classList.remove("is-error");
      pill.classList.add("is-scanning");
    }
    if (pillLabel) pillLabel.textContent = "Probing Wire...";
    if (gearBtn) gearBtn.classList.add("is-spinning");

    let activeIdx = 0;
    const pulseStep = () => {
      stages.forEach((st, i) => {
        st.classList.remove("is-done");
        st.classList.toggle("is-active", i === activeIdx);
      });
      activeIdx = (activeIdx + 1) % stages.length;
    };
    pulseStep();
    pipelineAnimTimer = setInterval(pulseStep, 260);
  } else {
    track.classList.remove("is-scanning");
    if (pill) pill.classList.remove("is-scanning");
    if (gearBtn) gearBtn.classList.remove("is-spinning");
    stages.forEach((st) => st.classList.remove("is-active"));
  }
}

function updatePipelineCounts(data) {
  const track = document.getElementById("scan-pipeline-bar");
  const pill = document.getElementById("engine-status-pill");
  const pillLabel = document.getElementById("engine-status-label");
  if (!track || !data) return;

  const counts = { L1: 0, L2: 0, L3: 0, L4: 0, L5: 0 };
  (data.algorithmEvidence || []).forEach((ev) => {
    const prefix = String(ev.layer || "").slice(0, 2);
    if (prefix in counts) counts[prefix] += 1;
  });

  Object.entries(counts).forEach(([layerKey, count]) => {
    const stage = track.querySelector(`.pipeline-stage[data-layer="${layerKey}"]`);
    const badge = track.querySelector(`[data-count-for="${layerKey}"]`);
    if (badge) badge.textContent = String(count);
    if (stage) {
      stage.classList.remove("is-active");
      stage.classList.toggle("is-done", count > 0 && !data.isGhost);
    }
  });

  if (pill && pillLabel) {
    pill.classList.toggle("is-error", Boolean(data.isGhost || data.isInvalid));
    if (data.isInvalid) pillLabel.textContent = "Validation Rejected";
    else if (data.isGhost) pillLabel.textContent = "NXDOMAIN / 404";
    else if (data.partialScan) pillLabel.textContent = "Partial Wire Scan";
    else pillLabel.textContent = data.cached ? "Verified (Cached)" : "Live Verified";
  }
}

function updateTelemetryStrip(data) {
  const statusEl = document.getElementById("metric-http-status");
  const latencyEl = document.getElementById("metric-latency");
  const countEl = document.getElementById("metric-tech-count");
  const domEl = document.getElementById("metric-dom-size");

  if (!data) return;

  if (statusEl) {
    statusEl.classList.remove("status-ok", "status-warn", "status-err");
    if (data.isInvalid) {
      statusEl.textContent = "400 Invalid";
      statusEl.classList.add("status-warn");
    } else if (data.isGhost) {
      statusEl.textContent = data.httpStatus ? `HTTP ${data.httpStatus}` : "NXDOMAIN";
      statusEl.classList.add("status-err");
    } else if (data.httpStatus >= 200 && data.httpStatus < 400) {
      statusEl.textContent = `HTTP ${data.httpStatus} OK`;
      statusEl.classList.add("status-ok");
    } else if (data.httpStatus > 0) {
      statusEl.textContent = `HTTP ${data.httpStatus}`;
      statusEl.classList.add("status-warn");
    } else {
      statusEl.textContent = "DNS Wire";
      statusEl.classList.add("status-warn");
    }
  }

  animateMetric(latencyEl, data.responseTimeMs ? Math.round(data.responseTimeMs) : null, " ms");
  animateMetric(countEl, data.totalCount || 0, "");

  if (domEl) {
    if (data.domMetrics && data.domMetrics.htmlBytes > 0) {
      const assets = (data.domMetrics.scriptCount || 0) + (data.domMetrics.stylesheetCount || 0);
      domEl.textContent = `${formatBytes(data.domMetrics.htmlBytes)} / ${assets} assets`;
    } else {
      domEl.textContent = data.isGhost ? "0 B" : "Headers/DNS";
    }
  }
}

// ==========================================================================
// SLIDING TAB INDICATOR CONTROLLER
// ==========================================================================
function updateTabIndicator() {
  const indicator = document.getElementById("popup-tab-indicator");
  const activeBtn = document.querySelector(".popup-tab-btn.active");
  if (!indicator || !activeBtn) return;

  indicator.style.width = `${activeBtn.offsetWidth}px`;
  indicator.style.transform = `translateX(${activeBtn.offsetLeft}px)`;
}

function switchPopupTab(tabKey) {
  state.activeTab = tabKey;

  const map = {
    technologies: { btn: "tab-technologies", panel: "panel-technologies" },
    "more-info": { btn: "tab-more-info", panel: "popup-more-info-panel" },
    "wire-trace": { btn: "tab-wire-trace", panel: "popup-wire-trace-panel" }
  };

  Object.entries(map).forEach(([key, cfg]) => {
    const btn = document.getElementById(cfg.btn);
    const panel = document.getElementById(cfg.panel);
    const isActive = key === tabKey;
    if (btn) {
      btn.classList.toggle("active", isActive);
      btn.setAttribute("aria-selected", String(isActive));
    }
    if (panel) {
      panel.style.display = isActive ? "block" : "none";
      panel.classList.toggle("active", isActive);
    }
  });

  updateTabIndicator();
}

// ==========================================================================
// SHIMMER SKELETON & PAUSED VIEWS
// ==========================================================================
function syncActiveChip(domain) {
  const norm = normalizeDomain(domain);
  document.querySelectorAll(".quick-chip").forEach((chip) => {
    const chipDomain = normalizeDomain(chip.getAttribute("data-domain") || "");
    chip.classList.toggle("active", chipDomain === norm);
  });
}

function renderSkeletonState(targetDomain) {
  const pill = document.getElementById("popup-active-domain");
  if (pill) pill.textContent = targetDomain;

  const filterBar = document.getElementById("popup-filter-bar");
  if (filterBar) filterBar.style.display = "none";

  const container = document.getElementById("popup-columns-container");
  if (!container) return;

  const makeSkeletonCol = () => `
    <div class="skeleton-col">
      <div class="skeleton-group">
        <div class="skeleton-line" style="width: 34%;"></div>
        <div class="skeleton-row"><div class="skeleton-circle"></div><div class="skeleton-line" style="width: 58%;"></div></div>
        <div class="skeleton-row"><div class="skeleton-circle"></div><div class="skeleton-line" style="width: 44%;"></div></div>
      </div>
      <div class="skeleton-group">
        <div class="skeleton-line" style="width: 42%;"></div>
        <div class="skeleton-row"><div class="skeleton-circle"></div><div class="skeleton-line" style="width: 64%;"></div></div>
      </div>
      <div class="skeleton-group">
        <div class="skeleton-line" style="width: 38%;"></div>
        <div class="skeleton-row"><div class="skeleton-circle"></div><div class="skeleton-line" style="width: 52%;"></div></div>
        <div class="skeleton-row"><div class="skeleton-circle"></div><div class="skeleton-line" style="width: 48%;"></div></div>
      </div>
    </div>
  `;

  container.innerHTML = `${makeSkeletonCol()}${makeSkeletonCol()}`;
}

function renderPausedState() {
  const filterBar = document.getElementById("popup-filter-bar");
  if (filterBar) filterBar.style.display = "none";

  const container = document.getElementById("popup-columns-container");
  if (!container) return;
  container.innerHTML = `
    <div style="grid-column: 1 / -1; padding: 48px 24px; text-align: center;">
      <div style="font-size: 15px; font-weight: 700; color: #1e1160; margin-bottom: 6px;">
        Deteksi Ekstensi Dijeda
      </div>
      <div style="font-size: 13px; color: #6b7280; max-width: 380px; margin: 0 auto; line-height: 1.55;">
        Aktifkan kembali sakelar di pojok kanan atas kartu Wappalyzer untuk melanjutkan pemindaian langsung.
      </div>
    </div>
  `;
}

// ==========================================================================
// LIVE SCAN EXECUTOR (ABORT + RACE-CONDITION SAFE)
// ==========================================================================
async function runTechnologyScan(targetDomain, { fresh = false } = {}) {
  if (!state.isExtensionActive) {
    renderPausedState();
    showToast("Deteksi sedang dijeda. Aktifkan sakelar ekstensi terlebih dahulu.");
    return;
  }

  const domainInput = document.getElementById("scan-domain-input");
  const rawTarget = targetDomain !== undefined ? targetDomain : (domainInput ? domainInput.value.trim() : "");
  if (!rawTarget) return;

  if (activeAbortController) {
    activeAbortController.abort();
  }
  activeAbortController = new AbortController();
  const scanId = ++activeScanId;

  const submitBtn = document.getElementById("scan-submit-btn");
  const btnText = document.getElementById("scan-btn-text");
  const spinner = document.getElementById("scan-spinner");

  state.isScanning = true;
  state.techSearchQuery = "";
  state.activeEvidenceLayer = "ALL";
  state.highlightedEvidenceId = null;

  const filterInput = document.getElementById("tech-filter-input");
  if (filterInput) filterInput.value = "";

  if (submitBtn) submitBtn.disabled = true;
  if (btnText) btnText.style.display = "none";
  if (spinner) spinner.style.display = "inline-block";

  const displayTarget = normalizeDomain(rawTarget) || rawTarget;
  syncActiveChip(displayTarget);
  setPipelineScanning(true);
  renderSkeletonState(displayTarget);

  try {
    const analysis = await analyzeTargetUrl(rawTarget, {
      signal: activeAbortController.signal,
      fresh
    });

    if (scanId !== activeScanId) return;

    state.currentScanDomain = analysis.domain;
    state.currentScanData = analysis;

    setPipelineScanning(false);
    updatePipelineCounts(analysis);
    updateTelemetryStrip(analysis);
    renderScanResults();

    if (analysis.isInvalid) {
      showToast(analysis.ghostReason || "Format domain tidak valid");
    } else if (analysis.isGhost) {
      showToast(`Host tidak ditemukan: ${analysis.domain}`);
    } else {
      showToast(`${analysis.totalCount} technologies detected for ${analysis.domain}`);
    }
  } catch (err) {
    if (err && err.name === "AbortError") return;
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
      redirectChain: [],
      rawHeaders: {},
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
    setPipelineScanning(false);
    updatePipelineCounts(state.currentScanData);
    updateTelemetryStrip(state.currentScanData);
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

// ==========================================================================
// RENDER ALL 3 POPUP VIEWS (TECHNOLOGIES, MORE INFO, WIRE TRACE)
// ==========================================================================
function renderScanResults() {
  const data = state.currentScanData;
  if (!data) return;

  const domainPill = document.getElementById("popup-active-domain");
  if (domainPill) domainPill.textContent = data.domain;

  renderTechnologiesColumnView(data);
  renderMoreInfoEvidenceView(data);
  renderWireTraceView(data);
  updateTabIndicator();
}

function renderTechnologiesColumnView(data) {
  const container = document.getElementById("popup-columns-container");
  const filterBar = document.getElementById("popup-filter-bar");
  const filterCount = document.getElementById("tech-filter-count");
  if (!container) return;

  container.innerHTML = "";

  if (data.isGhost || data.totalCount === 0) {
    if (filterBar) filterBar.style.display = "none";
    const titleText = data.isInvalid
      ? "Input Domain Tidak Valid atau Diblokir"
      : data.isGhost
        ? "Host Tidak Ditemukan (NXDOMAIN / 404)"
        : "Tidak Ada Tanda Tangan Teknologi Terdeteksi";
    const descText = data.ghostReason || data.scanNote || `Target ${data.domain} tidak mengembalikan sinyal teknologi yang dapat diverifikasi.`;

    container.innerHTML = `
      <div style="grid-column: 1 / -1; padding: 48px 24px; text-align: center;">
        <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="${data.isInvalid ? "#d97706" : "#dc2626"}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-bottom: 12px; display: inline-block;">
          <circle cx="12" cy="12" r="10"></circle>
          <line x1="12" y1="8" x2="12" y2="12"></line>
          <line x1="12" y1="16" x2="12.01" y2="16"></line>
        </svg>
        <div style="font-size: 15px; font-weight: 700; color: #1e1160; margin-bottom: 6px;">
          ${escapeHtml(titleText)}
        </div>
        <div style="font-size: 13px; color: #6b7280; max-width: 440px; margin: 0 auto; line-height: 1.55;">
          ${escapeHtml(descText)}
        </div>
      </div>
    `;
    return;
  }

  if (filterBar) {
    filterBar.style.display = data.totalCount >= 5 ? "flex" : "none";
  }

  const query = state.techSearchQuery.trim().toLowerCase();
  const filterGroups = (groups) => {
    if (!query) return groups;
    return groups
      .map((g) => {
        const catMatch = g.category.toLowerCase().includes(query);
        const items = catMatch
          ? g.items
          : g.items.filter((it) => it.name.toLowerCase().includes(query) || (it.version && it.version.toLowerCase().includes(query)));
        return { category: g.category, items };
      })
      .filter((g) => g.items.length > 0);
  };

  const leftFiltered = filterGroups(data.leftColumn || []);
  const rightFiltered = filterGroups(data.rightColumn || []);
  const shownCount = [...leftFiltered, ...rightFiltered].reduce((sum, g) => sum + g.items.length, 0);

  if (filterCount) {
    filterCount.textContent = query ? `${shownCount}/${data.totalCount}` : `${data.totalCount} detected`;
  }

  if (shownCount === 0) {
    container.innerHTML = `
      <div style="grid-column: 1 / -1; padding: 36px 20px; text-align: center; color: #6b7280; font-size: 13px;">
        Tidak ada teknologi yang cocok dengan filter "${escapeHtml(state.techSearchQuery)}".
      </div>
    `;
    return;
  }

  const leftCol = document.createElement("div");
  leftCol.className = "popup-column left-column";
  const rightCol = document.createElement("div");
  rightCol.className = "popup-column right-column";

  let rowCounter = 0;
  leftFiltered.forEach((group, gIdx) => {
    const el = createCategoryGroupEl(group, gIdx, () => rowCounter++);
    leftCol.appendChild(el);
  });
  rightFiltered.forEach((group, gIdx) => {
    const el = createCategoryGroupEl(group, gIdx + leftFiltered.length, () => rowCounter++);
    rightCol.appendChild(el);
  });

  container.appendChild(leftCol);
  container.appendChild(rightCol);
}

function createCategoryGroupEl(group, groupIdx, nextRowIdx) {
  const groupEl = document.createElement("div");
  groupEl.className = "category-group";
  groupEl.style.setProperty("--group-idx", String(groupIdx));

  const titleEl = document.createElement("div");
  titleEl.className = "category-title";
  titleEl.textContent = group.category;
  groupEl.appendChild(titleEl);

  const listEl = document.createElement("div");
  listEl.className = "tech-items-list";

  group.items.forEach((item) => {
    const row = document.createElement("div");
    row.className = "tech-item-row";
    row.style.setProperty("--row-idx", String(nextRowIdx()));

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

    if (item.evidenceId) {
      const proofBtn = document.createElement("button");
      proofBtn.type = "button";
      proofBtn.className = "tech-proof-btn";
      proofBtn.textContent = "Proof";
      proofBtn.title = "Inspect matching wire/DOM rule";
      proofBtn.addEventListener("click", () => {
        state.activeEvidenceLayer = "ALL";
        state.highlightedEvidenceId = item.evidenceId;
        renderMoreInfoEvidenceView(state.currentScanData);
        switchPopupTab("more-info");
      });
      row.appendChild(proofBtn);
    }

    listEl.appendChild(row);
  });

  groupEl.appendChild(listEl);
  return groupEl;
}

function renderMoreInfoEvidenceView(data) {
  const panel = document.getElementById("popup-more-info-panel");
  if (!panel) return;

  const isGhost = Boolean(data.isGhost);
  const isInvalid = Boolean(data.isInvalid);
  const isPartial = Boolean(data.partialScan);

  let statusHtml = `<span style="color:#059669; font-weight:700;">HTTP ${escapeHtml(data.httpStatus || 200)} OK</span>`;
  if (isInvalid) statusHtml = `<span style="color:#d97706; font-weight:700;">Input Ditolak / Diblokir</span>`;
  else if (isGhost) statusHtml = `<span style="color:#dc2626; font-weight:700;">Host Unreachable / NXDOMAIN</span>`;
  else if (isPartial && data.httpStatus > 0) statusHtml = `<span style="color:#d97706; font-weight:700;">HTTP ${escapeHtml(data.httpStatus)} (WAF / Partial)</span>`;
  else if (isPartial) statusHtml = `<span style="color:#2563eb; font-weight:700;">DNS Active (Partial Wire)</span>`;

  const allEvidence = data.algorithmEvidence || [];
  const filteredEvidence = state.activeEvidenceLayer === "ALL"
    ? allEvidence
    : allEvidence.filter((ev) => String(ev.layer || "").startsWith(state.activeEvidenceLayer));

  const layers = ["ALL", "L1", "L2", "L3", "L4", "L5"];
  const pillsHtml = layers.map((l) => {
    const count = l === "ALL" ? allEvidence.length : allEvidence.filter((ev) => String(ev.layer || "").startsWith(l)).length;
    return `<button type="button" class="layer-pill ${state.activeEvidenceLayer === l ? "active" : ""}" data-ev-layer="${l}">${l} (${count})</button>`;
  }).join("");

  const evidenceRows = filteredEvidence.map((ev) => `
    <tr class="${state.highlightedEvidenceId === ev.id ? "is-highlighted" : ""}">
      <td class="ev-id-cell">${escapeHtml(ev.id)}</td>
      <td><span class="ev-layer-badge ${isGhost ? "is-err" : ""}">${escapeHtml(ev.layer)}</span></td>
      <td style="font-weight:600;">${escapeHtml(ev.tech)}</td>
      <td class="ev-rule-cell">${escapeHtml(ev.rule)}</td>
      <td class="ev-detail-cell">${escapeHtml(ev.detail || "-")}</td>
      <td class="ev-conf-cell" style="color:${isGhost ? "#dc2626" : "#059669"};">${escapeHtml(ev.confidence)}</td>
    </tr>
  `).join("");

  const targetHref = safeHttpUrl(data.finalUrl || `https://${data.domain}`);
  const scanNoteHtml = data.scanNote
    ? `<div class="info-notice-banner">${escapeHtml(data.scanNote)}</div>`
    : "";

  panel.innerHTML = `
    <div class="info-summary-grid">
      <div><strong>Target:</strong> <a href="${escapeHtml(targetHref)}" target="_blank" rel="noopener noreferrer" style="color:#1d64e8; font-weight:600;">${escapeHtml(data.finalUrl || `https://${data.domain}`)}</a></div>
      <div><strong>Status:</strong> ${statusHtml}</div>
      <div><strong>Server:</strong> <span>${escapeHtml(data.serverLocation || "Global Edge")}</span></div>
      <div><strong>Response:</strong> <span>${data.responseTimeMs ? `${escapeHtml(data.responseTimeMs)} ms` : "N/A"}</span></div>
      <div><strong>Protocol:</strong> <span>${escapeHtml(data.tlsVersion || "HTTPS / TLS")}</span></div>
    </div>
    ${scanNoteHtml}
    <div class="evidence-controls">
      <strong class="wire-section-title">Signature Match Evidence</strong>
      <div class="layer-filter-pills">${pillsHtml}</div>
    </div>
    <div class="evidence-table-wrap">
      <table class="evidence-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Layer</th>
            <th>Technology</th>
            <th>Match Rule</th>
            <th>Wire / DOM Artifact</th>
            <th>Conf.</th>
          </tr>
        </thead>
        <tbody>
          ${evidenceRows || `<tr><td colspan="6" style="text-align:center; padding:18px; color:#6b7280;">Tidak ada bukti pada layer ${escapeHtml(state.activeEvidenceLayer)}.</td></tr>`}
        </tbody>
      </table>
    </div>
  `;

  panel.querySelectorAll(".layer-pill").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.activeEvidenceLayer = btn.getAttribute("data-ev-layer") || "ALL";
      state.highlightedEvidenceId = null;
      renderMoreInfoEvidenceView(data);
    });
  });
}

function renderWireTraceView(data) {
  const panel = document.getElementById("popup-wire-trace-panel");
  if (!panel) return;

  const hops = Array.isArray(data.redirectChain) ? data.redirectChain : [];
  const hopsHtml = hops.length > 0
    ? hops.map((hop) => {
        const sClass = hop.status >= 500 ? "s5xx" : hop.status >= 400 ? "s4xx" : hop.status >= 300 ? "s3xx" : "s2xx";
        return `
          <div class="hop-item">
            <span style="color:#6b7280;">#${escapeHtml(hop.hop)}</span>
            <span class="hop-status-pill ${sClass}">HTTP ${escapeHtml(hop.status)}</span>
            <span style="color:#111827; word-break:break-all; flex:1;">${escapeHtml(hop.url)}</span>
            <span style="color:#6b7280;">${escapeHtml(hop.latencyMs)} ms</span>
          </div>
        `;
      }).join("")
    : `<div class="dns-kv-card" style="color:#6b7280;">Tidak ada redirect chain HTTP (koneksi DNS-only atau host tidak terjangkau).</div>`;

  const dns = data.dns || {};
  const dnsCards = [
    { key: "A / IPv4", val: (dns.ips && dns.ips.length ? dns.ips.join(", ") : dns.ip) || "None" },
    { key: "CNAME", val: dns.cname || "None" },
    { key: "Nameservers (NS)", val: dns.nameservers && dns.nameservers.length ? dns.nameservers.join(", ") : "None" },
    { key: "Mail Exchangers (MX)", val: dns.mx && dns.mx.length ? dns.mx.slice(0, 3).join(", ") : "None" }
  ].map((item) => `
    <div class="dns-kv-card">
      <div class="dns-kv-key">${escapeHtml(item.key)}</div>
      <div class="dns-kv-val">${escapeHtml(item.val)}</div>
    </div>
  `).join("");

  const headerEntries = Object.entries(data.rawHeaders || {});
  const headersHtml = headerEntries.length > 0
    ? headerEntries.map(([k, v]) => `
        <div class="raw-header-line">
          <span class="raw-header-k">${escapeHtml(k)}:</span>
          <span class="raw-header-v">${escapeHtml(v)}</span>
        </div>
      `).join("")
    : `<div style="color:#6b7280;">Tidak ada HTTP response headers yang diterima.</div>`;

  const dm = data.domMetrics;
  const domHtml = dm
    ? `
      <div class="dns-kv-grid">
        <div class="dns-kv-card"><div class="dns-kv-key">HTML Inspected</div><div class="dns-kv-val">${escapeHtml(formatBytes(dm.htmlBytes))}</div></div>
        <div class="dns-kv-card"><div class="dns-kv-key">Meta Tags</div><div class="dns-kv-val">${escapeHtml(dm.metaCount)}</div></div>
        <div class="dns-kv-card"><div class="dns-kv-key">External Scripts</div><div class="dns-kv-val">${escapeHtml(dm.scriptCount)}</div></div>
        <div class="dns-kv-card"><div class="dns-kv-key">Link / Stylesheets</div><div class="dns-kv-val">${escapeHtml(dm.stylesheetCount)}</div></div>
      </div>
    `
    : `<div class="dns-kv-card" style="color:#6b7280;">DOM tidak diekstraksi pada pemindaian ini.</div>`;

  panel.innerHTML = `
    <div class="wire-section">
      <div class="wire-section-header">
        <strong class="wire-section-title">HTTP Redirect Trace (${hops.length} hop)</strong>
      </div>
      <div class="hop-chain">${hopsHtml}</div>
    </div>

    <div class="wire-section">
      <div class="wire-section-header">
        <strong class="wire-section-title">Live Authoritative DNS Records</strong>
      </div>
      <div class="dns-kv-grid">${dnsCards}</div>
    </div>

    <div class="wire-section">
      <div class="wire-section-header">
        <strong class="wire-section-title">Sanitized HTTP Response Headers (${headerEntries.length})</strong>
        <button type="button" class="wire-copy-btn" id="copy-raw-headers-btn">Copy JSON</button>
      </div>
      <div class="raw-headers-box">${headersHtml}</div>
    </div>

    <div class="wire-section">
      <div class="wire-section-header">
        <strong class="wire-section-title">DOM Extraction Metrics</strong>
      </div>
      ${domHtml}
    </div>
  `;

  const copyBtn = document.getElementById("copy-raw-headers-btn");
  if (copyBtn) {
    copyBtn.addEventListener("click", () => {
      const payload = JSON.stringify({
        domain: data.domain,
        finalUrl: data.finalUrl,
        httpStatus: data.httpStatus,
        redirectChain: data.redirectChain,
        dns: data.dns,
        rawHeaders: data.rawHeaders,
        domMetrics: data.domMetrics
      }, null, 2);
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(payload).then(() => {
          showToast("Wire trace JSON disalin ke clipboard");
        }).catch(() => {});
      }
    });
  }
}

// Export Full Stack + Wire Trace JSON
function exportTechStack() {
  if (!state.currentScanData) return;
  const d = state.currentScanData;
  const payload = {
    domain: state.currentScanDomain,
    finalUrl: d.finalUrl || `https://${state.currentScanDomain}`,
    httpStatus: d.httpStatus ?? null,
    responseTimeMs: d.responseTimeMs ?? null,
    totalCount: d.totalCount,
    leftColumn: d.leftColumn,
    rightColumn: d.rightColumn,
    evidence: d.algorithmEvidence || [],
    redirectChain: d.redirectChain || [],
    dns: d.dns || null,
    rawHeaders: d.rawHeaders || {},
    domMetrics: d.domMetrics || null
  };

  const jsonString = JSON.stringify(payload, null, 2);
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(jsonString).catch(() => {});
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

  showToast(`Exported ${d.totalCount} technologies & wire trace for ${state.currentScanDomain}`);
}

// XSS-Safe Toast Notifications
function showToast(message) {
  const container = document.getElementById("toast-container");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = "toast";

  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("width", "16");
  svg.setAttribute("height", "16");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2.4");
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
    toast.style.transform = "translateX(28px)";
    toast.style.transition = "opacity 240ms ease, transform 240ms ease";
    setTimeout(() => toast.remove(), 260);
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

// ==========================================================================
// APPLICATION BOOTSTRAP
// ==========================================================================
document.addEventListener("DOMContentLoaded", () => {
  applyTheme(state.theme);
  applyTranslations();
  initHeroMotionCanvas();
  initScrollChoreography();

  // Position sliding tab indicator on load & resize
  requestAnimationFrame(updateTabIndicator);
  window.addEventListener("resize", updateTabIndicator, { passive: true });

  const scanInput = document.getElementById("scan-domain-input");
  const initialDomain = (scanInput && scanInput.value.trim()) || state.currentScanDomain;
  if (scanInput) scanInput.value = initialDomain;

  runTechnologyScan(initialDomain);

  // Popup Switch Toggle
  const popupSwitch = document.getElementById("popup-switch");
  const toggleExtensionState = () => {
    state.isExtensionActive = !state.isExtensionActive;
    popupSwitch.classList.toggle("active", state.isExtensionActive);
    popupSwitch.setAttribute("aria-checked", String(state.isExtensionActive));
    if (state.isExtensionActive) {
      showToast("Extension detection active");
      runTechnologyScan(scanInput ? scanInput.value.trim() : state.currentScanDomain);
    } else {
      if (activeAbortController) activeAbortController.abort();
      setPipelineScanning(false);
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

  // Force Fresh Live Scan Button
  const gearBtn = document.getElementById("popup-gear-btn");
  if (gearBtn) {
    gearBtn.addEventListener("click", () => {
      const target = (scanInput && scanInput.value.trim()) || state.currentScanDomain;
      showToast(`Memindai ulang ${normalizeDomain(target) || target} (fresh live scan)...`);
      runTechnologyScan(target, { fresh: true });
    });
  }

  // Popup 3-Tab Switcher
  document.querySelectorAll(".popup-tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const tabKey = btn.getAttribute("data-tab");
      if (tabKey) switchPopupTab(tabKey);
    });
  });

  // Inline Stack Filter Input
  const techFilterInput = document.getElementById("tech-filter-input");
  if (techFilterInput) {
    techFilterInput.addEventListener("input", (e) => {
      state.techSearchQuery = e.target.value;
      if (state.currentScanData) {
        renderTechnologiesColumnView(state.currentScanData);
      }
    });
  }

  // Export Button
  const exportBtn = document.getElementById("popup-export-btn");
  if (exportBtn) exportBtn.addEventListener("click", exportTechStack);

  // Theme & Language Toggles
  const themeBtn = document.getElementById("theme-toggle-btn");
  if (themeBtn) themeBtn.addEventListener("click", toggleTheme);

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

  // Smart auto-scan on input (600ms debounce, only for syntactically valid FQDNs)
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
          <input type="text" id="modal-search-field" class="scan-input" style="padding:0 14px;" placeholder="${escapeHtml(t("modal.searchPlaceholder"))}" autofocus>
          <button type="submit" class="scan-submit-btn">Scan</button>
        </form>
        <div style="font-size:13px; color:var(--color-on-surface-variant); line-height: 1.65;">
          <div style="margin-bottom:8px; font-weight:600;">Detected Capability Matrix:</div>
          <ul style="list-style:inside disc; display:grid; grid-template-columns:1fr 1fr; gap:6px;">
            <li>Web Frameworks (Next.js, Laravel, Rails)</li>
            <li>CMS &amp; Builders (WordPress, Elementor)</li>
            <li>Security &amp; WAF (F5 BIG-IP, Cloudflare)</li>
            <li>CDN &amp; Edge (Vercel, Fastly, jsDelivr)</li>
            <li>JS Libraries (jQuery, Swiper, GSAP)</li>
            <li>Analytics (GA4, GTM, Clarity, Sentry)</li>
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

  // Terms & Privacy Modals
  const termsBtn = document.getElementById("terms-modal-trigger");
  if (termsBtn) {
    termsBtn.addEventListener("click", () => {
      openModal(
        t("modal.termsTitle"),
        `<p style="font-size:14px; line-height:1.65; color:var(--color-on-surface-variant);">${escapeHtml(t("modal.termsBody"))}</p>`
      );
    });
  }

  const privacyBtn = document.getElementById("privacy-modal-trigger");
  if (privacyBtn) {
    privacyBtn.addEventListener("click", () => {
      openModal(
        t("modal.privacyTitle"),
        `<p style="font-size:14px; line-height:1.65; color:var(--color-on-surface-variant);">${escapeHtml(t("modal.privacyBody"))}</p>`
      );
    });
  }

  const modalCloseBtn = document.getElementById("modal-close-btn");
  if (modalCloseBtn) modalCloseBtn.addEventListener("click", closeModal);

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
