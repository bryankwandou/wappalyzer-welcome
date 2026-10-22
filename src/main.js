import { en } from "./locales/en.js";
import { id } from "./locales/id.js";
import { analyzeTargetUrl } from "./data/techDatabase.js";

// State Management - 100% Public Access (No Login Required)
const state = {
  lang: localStorage.getItem("wappalyzer_lang") || (navigator.language.startsWith("id") ? "id" : "en"),
  theme: localStorage.getItem("wappalyzer_theme") || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"),
  currentScanDomain: "polri.go.id",
  currentScanResults: []
};

const dictionaries = { en, id };

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

  updateScanMetaUI();
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

// SVG Icon Generator for tech cards
function getTechIconSvg(iconName) {
  const svgs = {
    layers: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 2 7 12 12 22 7 12 2"></polygon><polyline points="2 17 12 22 22 17"></polyline><polyline points="2 12 12 17 22 12"></polyline></svg>`,
    code: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>`,
    server: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line></svg>`,
    cloud: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"></path></svg>`,
    palette: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="13.5" cy="6.5" r=".5"></circle><circle cx="17.5" cy="10.5" r=".5"></circle><circle cx="8.5" cy="7.5" r=".5"></circle><circle cx="6.5" cy="12.5" r=".5"></circle><path d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10c.926 0 1.648-.746 1.648-1.688 0-.437-.18-.835-.437-1.125-.29-.289-.438-.652-.438-1.125a1.64 1.64 0 0 1 1.668-1.668h1.996c3.051 0 5.555-2.503 5.555-5.554C21.965 6.012 17.461 2 12 2z"></path></svg>`,
    shield: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>`,
    globe: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1 4-10z"></path></svg>`,
    "shopping-bag": `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 2L3 6v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6l-3-4z"></path><line x1="3" y1="6" x2="21" y2="6"></line><path d="M16 10a4 4 0 0 1-8 0"></path></svg>`,
    tag: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"></path><line x1="7" y1="7" x2="7.01" y2="7"></line></svg>`,
    "file-code": `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="10" y1="13" x2="8" y2="15"></line><line x1="8" y1="15" x2="10" y2="17"></line><line x1="14" y1="13" x2="16" y2="15"></line><line x1="16" y1="15" x2="14" y2="17"></line></svg>`,
    "credit-card": `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="1" y="4" width="22" height="16" rx="2" ry="2"></rect><line x1="1" y1="10" x2="23" y2="10"></line></svg>`,
    search: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>`,
    "bar-chart": `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="20" x2="12" y2="10"></line><line x1="18" y1="20" x2="18" y2="4"></line><line x1="6" y1="20" x2="6" y2="16"></line></svg>`,
    "share-2": `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="5" r="3"></circle><circle cx="6" cy="12" r="3"></circle><circle cx="18" cy="19" r="3"></circle><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"></line><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"></line></svg>`
  };
  return svgs[iconName] || svgs.layers;
}

// Execute Scan
function runTechnologyScan(targetDomain) {
  const domainInput = document.getElementById("scan-domain-input");
  const domainToScan = targetDomain || (domainInput ? domainInput.value.trim() : "");

  if (!domainToScan) return;

  const submitBtn = document.getElementById("scan-submit-btn");
  const btnText = document.getElementById("scan-btn-text");
  const spinner = document.getElementById("scan-spinner");

  if (submitBtn) submitBtn.disabled = true;
  if (btnText) btnText.style.display = "none";
  if (spinner) spinner.style.display = "inline-block";

  setTimeout(() => {
    const analysis = analyzeTargetUrl(domainToScan);
    state.currentScanDomain = analysis.domain;
    state.currentScanResults = analysis.results;

    renderScanResults();

    if (submitBtn) submitBtn.disabled = false;
    if (btnText) btnText.style.display = "inline";
    if (spinner) spinner.style.display = "none";

    showToast(`${analysis.results.length} technologies found on ${analysis.domain}`);
  }, 300);
}

function updateScanMetaUI() {
  const domainEl = document.getElementById("results-domain-name");
  const countEl = document.getElementById("results-count-text");

  if (domainEl) domainEl.textContent = state.currentScanDomain;
  if (countEl) {
    countEl.textContent = `${state.currentScanResults.length} ${t("scanner.scanCount")}`;
  }
}

function renderScanResults() {
  updateScanMetaUI();
  const grid = document.getElementById("tech-cards-grid");
  if (!grid) return;

  grid.innerHTML = "";

  if (state.currentScanResults.length === 0) {
    grid.innerHTML = `<div style="grid-column: 1 / -1; padding: 24px; text-align: center; color: var(--color-on-surface-disabled);">${t("scanner.noResults")}</div>`;
    return;
  }

  state.currentScanResults.forEach((tech) => {
    const card = document.createElement("div");
    card.className = "tech-card";

    const versionBadge = tech.version
      ? `<span class="tech-badge-version">${tech.version}</span>`
      : `<span class="tech-badge-version" style="opacity: 0.6;">Detected</span>`;

    card.innerHTML = `
      <div class="tech-card-header">
        <div class="tech-icon-wrap" aria-hidden="true">
          ${getTechIconSvg(tech.icon)}
        </div>
        ${versionBadge}
      </div>
      <div>
        <div class="tech-name">${tech.name}</div>
        <div class="tech-category">${tech.category}</div>
      </div>
      <div class="tech-meta-row">
        <span class="confidence-meter">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg>
          ${tech.confidence}%
        </span>
      </div>
    `;

    grid.appendChild(card);
  });
}

// Toast Notifications
function showToast(message) {
  const container = document.getElementById("toast-container");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = "toast";
  toast.innerHTML = `
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>
    <span>${message}</span>
  `;

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

  // Initial Scan directly for polri.go.id
  const initialData = analyzeTargetUrl("polri.go.id");
  state.currentScanDomain = initialData.domain;
  state.currentScanResults = initialData.results;
  renderScanResults();

  const scanInput = document.getElementById("scan-domain-input");
  if (scanInput) scanInput.value = "polri.go.id";

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
  if (scanForm) {
    scanForm.addEventListener("submit", (e) => {
      e.preventDefault();
      runTechnologyScan();
    });
  }

  // Quick Target Chips
  document.querySelectorAll(".quick-target-chip").forEach((chip) => {
    chip.addEventListener("click", () => {
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
        <div style="display:flex; gap:8px; margin-bottom:16px;">
          <input type="text" id="modal-search-field" class="scan-input" placeholder="${t("modal.searchPlaceholder")}" autofocus>
        </div>
        <div style="font-size:13px; color:var(--color-on-surface-variant); line-height: 1.6;">
          <div style="margin-bottom:8px; font-weight:600;">Popular Categories:</div>
          <ul style="list-style:inside disc; display:grid; grid-template-columns:1fr 1fr; gap:6px;">
            <li>Web Frameworks (Laravel, Next.js, Nuxt.js)</li>
            <li>Programming Languages (PHP, TypeScript)</li>
            <li>Security & WAF (F5 BIG-IP, Cloudflare)</li>
            <li>Content Management (WordPress, Ghost)</li>
            <li>CDN & Hosting (Vercel, jsDelivr)</li>
            <li>Analytics (Google Analytics 4, Mixpanel)</li>
          </ul>
        </div>
        `
      );
    });
  }

  // Terms Modal Trigger
  const termsBtn = document.getElementById("terms-modal-trigger");
  if (termsBtn) {
    termsBtn.addEventListener("click", () => {
      openModal(
        t("modal.termsTitle"),
        `<p style="font-size:14px; line-height:1.6; color:var(--color-on-surface-variant);">${t("modal.termsBody")}</p>`
      );
    });
  }

  // Privacy Modal Trigger
  const privacyBtn = document.getElementById("privacy-modal-trigger");
  if (privacyBtn) {
    privacyBtn.addEventListener("click", () => {
      openModal(
        t("modal.privacyTitle"),
        `<p style="font-size:14px; line-height:1.6; color:var(--color-on-surface-variant);">${t("modal.privacyBody")}</p>`
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
