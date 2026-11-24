/**
 * Wappalyzer 5-Layer Technographic Signature & Implication Engine
 * Shared pure module used by serverless live probes, dev middleware, and client-side DNS fallbacks.
 */

export const ENGINE_METADATA = {
  engine: "Wappalyzer Multi-Vector Signature Classifier",
  specification: "REA-MCP Reverse Engineering Protocol v45",
  version: "7.0.0",
  analysisLayers: [
    { id: "L1_NETWORK", name: "Network, DNS & Edge Transport", status: "ACTIVE" },
    { id: "L2_HEADERS", name: "HTTP Response Headers & Cookies", status: "ACTIVE" },
    { id: "L3_DOM_META", name: "HTML DOM, Meta & Embedded Assets", status: "ACTIVE" },
    { id: "L4_JS_GLOBALS", name: "Frontend Frameworks & JS Libraries", status: "ACTIVE" },
    { id: "L5_INFERRED", name: "Dependency Graph & Confidence Calibration", status: "ACTIVE" }
  ]
};

const MAX_HTML_BYTES = 512 * 1024;
const MAX_SNIPPET_LEN = 140;

const RESERVED_TLDS = new Set([
  "localhost",
  "local",
  "internal",
  "lan",
  "home",
  "corp",
  "intranet",
  "arpa",
  "localdomain"
]);

/**
 * Normalize raw user input into a lowercase hostname without scheme, credentials, port, or path.
 */
export function normalizeDomain(rawInput) {
  if (!rawInput || typeof rawInput !== "string") return "";
  let cleaned = rawInput.trim().toLowerCase();
  cleaned = cleaned.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
  cleaned = cleaned.split(/[/?#]/)[0];
  if (cleaned.includes("@")) {
    cleaned = cleaned.split("@").pop() || "";
  }
  // Strip IPv4/hostname port while keeping IPv6 intact for validator rejection
  if (!cleaned.startsWith("[") && cleaned.indexOf(":") === cleaned.lastIndexOf(":")) {
    cleaned = cleaned.split(":")[0];
  }
  cleaned = cleaned.replace(/^www\./, "");
  cleaned = cleaned.replace(/\.+$/, "");
  return cleaned;
}

/**
 * Validate RFC-1123 public FQDN and reject IP literals, private/reserved hosts, and .onion addresses.
 */
export function validateHostname(hostname) {
  if (!hostname || typeof hostname !== "string") {
    return { valid: false, code: "EMPTY", reason: "Masukkan nama domain yang valid (misalnya: github.com atau polri.go.id)." };
  }

  if (hostname.length > 253) {
    return { valid: false, code: "TOO_LONG", reason: "Nama domain melebihi batas maksimum 253 karakter." };
  }

  if (hostname.includes(":") || hostname.startsWith("[") || hostname.endsWith("]")) {
    return { valid: false, code: "IP_LITERAL_BLOCKED", reason: "Alamat IPv6 literal tidak diizinkan. Gunakan nama domain publik." };
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || /^\d+$/.test(hostname)) {
    return { valid: false, code: "IP_LITERAL_BLOCKED", reason: "Alamat IP literal tidak diizinkan demi keamanan SSRF. Gunakan nama domain publik." };
  }

  if (hostname === "localhost" || hostname.endsWith(".localhost")) {
    return { valid: false, code: "PRIVATE_HOST_BLOCKED", reason: "Host lokal (localhost) diblokir demi keamanan jaringan." };
  }

  if (hostname.endsWith(".onion")) {
    return { valid: false, code: "ONION_UNSUPPORTED", reason: "Alamat .onion hanya dapat diakses melalui jaringan Tor, bukan protokol HTTP/DNS publik." };
  }

  const labels = hostname.split(".");
  if (labels.length < 2) {
    return { valid: false, code: "MISSING_TLD", reason: `Input "${hostname}" bukan domain lengkap (harus memiliki TLD, misalnya .com, .id, atau .org).` };
  }

  const tld = labels[labels.length - 1];
  if (RESERVED_TLDS.has(tld)) {
    return { valid: false, code: "PRIVATE_HOST_BLOCKED", reason: `Domain internal (.${tld}) tidak dapat dipindai di jaringan publik.` };
  }

  if (!/^[a-z]{2,63}$|^xn--[a-z0-9-]{2,59}$/.test(tld)) {
    return { valid: false, code: "INVALID_TLD", reason: `Ekstensi TLD ".${tld}" tidak valid.` };
  }

  for (const label of labels) {
    if (!label || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) {
      return { valid: false, code: "INVALID_SYNTAX", reason: `Format hostname "${hostname}" tidak memenuhi standar RFC-1123.` };
    }
  }

  return { valid: true, code: "OK", reason: null };
}

/**
 * Detect private, loopback, link-local, CGNAT, and metadata IPv4/IPv6 addresses to block SSRF.
 */
export function isPrivateIp(ip) {
  if (!ip || typeof ip !== "string") return true;
  const trimmed = ip.trim().toLowerCase();

  // IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1)
  if (trimmed.startsWith("::ffff:")) {
    return isPrivateIp(trimmed.slice(7));
  }

  // IPv4 checks
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(trimmed)) {
    const parts = trimmed.split(".").map(Number);
    if (parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return true;
    const [a, b] = parts;
    if (a === 0) return true; // 0.0.0.0/8
    if (a === 10) return true; // 10.0.0.0/8
    if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
    if (a === 127) return true; // 127.0.0.0/8 loopback
    if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local / cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
    if (a === 192 && b === 168) return true; // 192.168.0.0/16
    if (a === 192 && b === 0 && parts[2] === 0) return true; // 192.0.0.0/24
    if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15 benchmark
    if (a >= 224) return true; // multicast / reserved
    return false;
  }

  // IPv6 checks
  if (trimmed.includes(":")) {
    if (trimmed === "::" || trimmed === "::1") return true;
    if (trimmed.startsWith("fe8") || trimmed.startsWith("fe9") || trimmed.startsWith("fea") || trimmed.startsWith("feb")) return true; // fe80::/10
    if (trimmed.startsWith("fc") || trimmed.startsWith("fd")) return true; // fc00::/7 ULA
    if (trimmed.startsWith("ff")) return true; // multicast
    return false;
  }

  return true;
}

function truncateSnippet(str, maxLen = MAX_SNIPPET_LEN) {
  if (!str) return "";
  const compact = String(str).replace(/\s+/g, " ").trim();
  return compact.length > maxLen ? `${compact.slice(0, maxLen - 3)}...` : compact;
}

function compareVersionSpecificity(vExisting, vNew) {
  if (!vNew) return vExisting || null;
  if (!vExisting) return vNew;
  const partsA = String(vExisting).split(".");
  const partsB = String(vNew).split(".");
  if (partsB.length > partsA.length) return vNew;
  return vExisting;
}

/**
 * Attribute-order-independent lightweight HTML parser for meta, script, link, and iframe extraction.
 */
export function parseHtmlSignals(rawHtml) {
  const html = typeof rawHtml === "string" ? rawHtml.slice(0, MAX_HTML_BYTES) : "";
  const htmlLower = html.toLowerCase();

  const metas = [];
  const metaRegex = /<meta\b([^>]{1,1000})>/gi;
  let m;
  while ((m = metaRegex.exec(html)) !== null) {
    const attrs = m[1];
    const nameMatch = attrs.match(/\bname\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
    const propMatch = attrs.match(/\bproperty\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
    const equivMatch = attrs.match(/\bhttp-equiv\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
    const contentMatch = attrs.match(/\bcontent\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
    const name = (nameMatch && (nameMatch[1] ?? nameMatch[2] ?? nameMatch[3])) || "";
    const property = (propMatch && (propMatch[1] ?? propMatch[2] ?? propMatch[3])) || "";
    const httpEquiv = (equivMatch && (equivMatch[1] ?? equivMatch[2] ?? equivMatch[3])) || "";
    const content = (contentMatch && (contentMatch[1] ?? contentMatch[2] ?? contentMatch[3])) || "";
    if (name || property || httpEquiv) {
      metas.push({
        name: name.toLowerCase(),
        property: property.toLowerCase(),
        httpEquiv: httpEquiv.toLowerCase(),
        content
      });
    }
  }

  const scriptSrcs = [];
  const scriptRegex = /<script\b[^>]*\bsrc\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))/gi;
  while ((m = scriptRegex.exec(html)) !== null) {
    const src = m[1] || m[2] || m[3] || "";
    if (src) scriptSrcs.push(src);
  }

  const linkHrefs = [];
  const linkTags = [];
  const linkRegex = /<link\b([^>]{1,1000})>/gi;
  while ((m = linkRegex.exec(html)) !== null) {
    const attrs = m[1];
    const hrefMatch = attrs.match(/\bhref\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))/i);
    const relMatch = attrs.match(/\brel\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))/i);
    const href = (hrefMatch && (hrefMatch[1] || hrefMatch[2] || hrefMatch[3])) || "";
    const rel = (relMatch && (relMatch[1] || relMatch[2] || relMatch[3])) || "";
    if (href) {
      linkHrefs.push(href);
      linkTags.push({ rel: rel.toLowerCase(), href });
    }
  }

  const iframeSrcs = [];
  const iframeRegex = /<iframe\b[^>]*\bsrc\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))/gi;
  while ((m = iframeRegex.exec(html)) !== null) {
    const src = m[1] || m[2] || m[3] || "";
    if (src) iframeSrcs.push(src);
  }

  const assetUrls = [...scriptSrcs, ...linkHrefs];

  return {
    html,
    htmlLower,
    metas,
    scriptSrcs,
    linkHrefs,
    linkTags,
    iframeSrcs,
    assetUrls
  };
}

/**
 * Dependency / Implication rules modeled after Wappalyzer's technology graph.
 */
const IMPLICATION_RULES = {
  "WordPress": [
    { category: "Blogs", name: "WordPress", icon: "wordpress", url: "https://wordpress.org", inheritVersion: true, confidence: 100 },
    { category: "Programming languages", name: "PHP", icon: "php", url: "https://www.php.net", confidence: 90 }
  ],
  "Elementor": [
    { category: "CMS", name: "WordPress", icon: "wordpress", url: "https://wordpress.org", confidence: 95 }
  ],
  "WooCommerce": [
    { category: "CMS", name: "WordPress", icon: "wordpress", url: "https://wordpress.org", confidence: 95 }
  ],
  "Yoast SEO": [
    { category: "CMS", name: "WordPress", icon: "wordpress", url: "https://wordpress.org", confidence: 95 }
  ],
  "WPBakery": [
    { category: "CMS", name: "WordPress", icon: "wordpress", url: "https://wordpress.org", confidence: 95 }
  ],
  "Divi": [
    { category: "CMS", name: "WordPress", icon: "wordpress", url: "https://wordpress.org", confidence: 95 }
  ],
  "Drupal": [
    { category: "Programming languages", name: "PHP", icon: "php", url: "https://www.php.net", confidence: 90 }
  ],
  "Joomla": [
    { category: "Programming languages", name: "PHP", icon: "php", url: "https://www.php.net", confidence: 90 }
  ],
  "Laravel": [
    { category: "Programming languages", name: "PHP", icon: "php", url: "https://www.php.net", confidence: 95 }
  ],
  "CodeIgniter": [
    { category: "Programming languages", name: "PHP", icon: "php", url: "https://www.php.net", confidence: 95 }
  ],
  "Next.js": [
    { category: "JavaScript frameworks", name: "React", icon: "react", url: "https://react.dev", confidence: 100 }
  ],
  "Gatsby": [
    { category: "JavaScript frameworks", name: "React", icon: "react", url: "https://react.dev", confidence: 100 }
  ],
  "Remix": [
    { category: "JavaScript frameworks", name: "React", icon: "react", url: "https://react.dev", confidence: 100 }
  ],
  "Nuxt.js": [
    { category: "JavaScript frameworks", name: "Vue.js", icon: "vue", url: "https://vuejs.org", confidence: 100 }
  ],
  "Vuetify": [
    { category: "JavaScript frameworks", name: "Vue.js", icon: "vue", url: "https://vuejs.org", confidence: 100 }
  ],
  "Express": [
    { category: "Programming languages", name: "Node.js", icon: "nodejs", url: "https://nodejs.org", confidence: 95 }
  ],
  "Ruby on Rails": [
    { category: "Programming languages", name: "Ruby", icon: "code", url: "https://www.ruby-lang.org", confidence: 95 }
  ],
  "Django": [
    { category: "Programming languages", name: "Python", icon: "python", url: "https://www.python.org", confidence: 95 }
  ],
  "Microsoft IIS": [
    { category: "Operating systems", name: "Windows Server", icon: "microsoft", url: "https://www.microsoft.com/windows-server", confidence: 85 }
  ],
  "Microsoft SharePoint": [
    { category: "Web frameworks", name: "ASP.NET", icon: "microsoft", url: "https://dotnet.microsoft.com/apps/aspnet", confidence: 90 }
  ],
  "jQuery UI": [
    { category: "JavaScript libraries", name: "jQuery", icon: "jquery", url: "https://jquery.com", confidence: 95 }
  ],
  "jQuery Migrate": [
    { category: "JavaScript libraries", name: "jQuery", icon: "jquery", url: "https://jquery.com", confidence: 95 }
  ],
  ".Select2": [
    { category: "JavaScript libraries", name: "jQuery", icon: "jquery", url: "https://jquery.com", confidence: 90 }
  ]
};

class DetectionRegistry {
  constructor() {
    this.categories = new Map();
    this.byName = new Map();
    this.evidenceMap = new Map();
    this.extraEvidence = [];
    this.counter = 0;
  }

  add({ category, name, version = null, icon = "code", url = "https://wappalyzer.com", confidence = 100, layer = "L3_DOM_META", rule = "", detail = "" }) {
    const cleanVer = version ? String(version).trim() : null;
    const numericConf = typeof confidence === "number" ? Math.min(100, Math.max(10, Math.round(confidence))) : parseInt(String(confidence), 10) || 100;

    if (!this.categories.has(category)) {
      this.categories.set(category, []);
    }
    const list = this.categories.get(category);
    const existing = list.find((item) => item.name === name);

    if (existing) {
      const upgradedVer = compareVersionSpecificity(existing.version, cleanVer);
      const upgradedConf = Math.max(existing._conf, numericConf);
      existing.version = upgradedVer;
      existing._conf = upgradedConf;
      existing.confidence = `${upgradedConf}%`;

      const evKey = `${category}::${name}`;
      const existingEv = this.evidenceMap.get(evKey);
      if (existingEv) {
        if (upgradedVer) {
          existingEv.tech = `${name} ${upgradedVer}`;
        }
        existingEv.confidence = `${upgradedConf}%`;
        // Prefer direct layer over inferred layer
        if (existingEv.layer === "L5_INFERRED" && layer !== "L5_INFERRED" && rule) {
          existingEv.layer = layer;
          existingEv.rule = truncateSnippet(rule, 100);
          existingEv.detail = truncateSnippet(detail || rule);
        } else if (cleanVer && detail && !existingEv.detail.includes(cleanVer)) {
          existingEv.detail = truncateSnippet(detail);
        }
      }
      this._syncNameIndex(name, existing);
      return;
    }

    this.counter += 1;
    const evId = `EVID-${layer.split("_")[0]}-${String(this.counter).padStart(2, "0")}`;
    const item = {
      name,
      version: cleanVer,
      icon,
      url,
      confidence: `${numericConf}%`,
      _conf: numericConf,
      evidenceId: evId
    };
    list.push(item);
    this._syncNameIndex(name, item);

    const techLabel = cleanVer ? `${name} ${cleanVer}` : name;
    this.evidenceMap.set(`${category}::${name}`, {
      id: evId,
      layer,
      tech: techLabel,
      rule: truncateSnippet(rule || `Signature match for ${name}`, 100),
      detail: truncateSnippet(detail || `Matched live wire/DOM artifact for ${name}`),
      confidence: `${numericConf}%`
    });
  }

  _syncNameIndex(name, item) {
    const prev = this.byName.get(name);
    if (!prev || (item.version && !prev.version) || item._conf > prev._conf) {
      this.byName.set(name, item);
    }
  }

  addNetworkEvidence({ id, layer = "L1_NETWORK", tech, rule, detail, confidence = "100%" }) {
    this.extraEvidence.push({
      id,
      layer,
      tech,
      rule: truncateSnippet(rule, 100),
      detail: truncateSnippet(detail),
      confidence
    });
  }

  resolveImplications() {
    // Fixed-point loop (max 4 passes) to resolve transitive implications like Elementor -> WordPress -> PHP & Blogs
    for (let pass = 0; pass < 4; pass++) {
      let added = false;
      const snapshot = Array.from(this.byName.entries());
      for (const [sourceName, sourceItem] of snapshot) {
        const impliedList = IMPLICATION_RULES[sourceName];
        if (!impliedList) continue;
        for (const target of impliedList) {
          const catList = this.categories.get(target.category);
          const alreadyInCat = catList && catList.some((it) => it.name === target.name);
          const targetVer = target.inheritVersion ? sourceItem.version : null;

          if (!alreadyInCat) {
            this.add({
              category: target.category,
              name: target.name,
              version: targetVer,
              icon: target.icon,
              url: target.url,
              confidence: target.confidence,
              layer: "L5_INFERRED",
              rule: `Implied by ${sourceName}`,
              detail: `Dependency graph inference: ${sourceName}${sourceItem.version ? " " + sourceItem.version : ""} implies ${target.name}`
            });
            added = true;
          } else if (target.inheritVersion && targetVer) {
            // Propagate version (e.g. CMS: WordPress 6.7 -> Blogs: WordPress 6.7)
            const existing = catList.find((it) => it.name === target.name);
            if (existing && !existing.version) {
              this.add({
                category: target.category,
                name: target.name,
                version: targetVer,
                icon: target.icon,
                url: target.url,
                confidence: target.confidence,
                layer: "L5_INFERRED",
                rule: `Version inherited from ${sourceName}`,
                detail: `Synchronized version ${targetVer} from detected ${sourceName}`
              });
            }
          }
        }
      }
      if (!added) break;
    }
  }

  build() {
    this.resolveImplications();

    const technologies = [];
    for (const [category, items] of this.categories.entries()) {
      technologies.push({
        category,
        items: items.map(({ _conf, ...clean }) => clean)
      });
    }

    const evidence = [...this.extraEvidence, ...Array.from(this.evidenceMap.values())];
    const totalCount = technologies.reduce((sum, group) => sum + group.items.length, 0);

    return { technologies, evidence, totalCount };
  }
}

function matchAsset(assetUrls, regex) {
  for (const url of assetUrls) {
    const m = url.match(regex);
    if (m) return { url, match: m };
  }
  return null;
}

/**
 * Extract exact semver version from standard CDN URLs (cdnjs, jsDelivr, unpkg) or ?ver= query params.
 */
export function extractAssetVersion(url, pkgPattern) {
  if (!url || typeof url !== "string") return null;
  const cdnPatterns = [
    new RegExp(`cdnjs\\.cloudflare\\.com/ajax/libs/${pkgPattern}/([\\d]+(?:\\.[\\d]+){1,3})/`, "i"),
    new RegExp(`cdn\\.jsdelivr\\.net/npm/${pkgPattern}@([\\d]+(?:\\.[\\d]+){1,3})`, "i"),
    new RegExp(`unpkg\\.com/${pkgPattern}@([\\d]+(?:\\.[\\d]+){1,3})`, "i"),
    new RegExp(`${pkgPattern}[/@.-]([\\d]+(?:\\.[\\d]+){1,3})`, "i"),
    /[?&]ver=([\d]+(?:\.[\d]+){1,3})/i
  ];
  for (const rx of cdnPatterns) {
    const m = url.match(rx);
    if (m && m[1]) return m[1];
  }
  return null;
}

/**
 * Core 5-Layer Live Signature Extractor.
 * Operates strictly on real HTTP headers, cookies, HTML DOM, and DNS wire signals.
 */
export function extractSignatures({
  domain = "",
  finalUrl = "",
  protocol = "https:",
  status = 0,
  headers = {},
  setCookies = [],
  html = "",
  dns = null
} = {}) {
  const reg = new DetectionRegistry();

  // Normalize headers to lowercase keys
  const h = {};
  for (const [k, v] of Object.entries(headers || {})) {
    if (v !== undefined && v !== null) {
      h[k.toLowerCase()] = String(v);
    }
  }

  const cookieList = Array.isArray(setCookies) ? setCookies.filter(Boolean).map(String) : [];
  if (h["set-cookie"] && cookieList.length === 0) {
    cookieList.push(h["set-cookie"]);
  }
  const cookieJoined = cookieList.join("; ");
  const cookieNames = cookieList
    .flatMap((raw) => raw.split(/,(?=[^;]+=)/))
    .map((part) => part.split("=")[0].trim().toLowerCase())
    .filter(Boolean);
  const hasCookie = (prefix) => cookieNames.some((c) => c === prefix || c.startsWith(prefix));

  // =========================================================================
  // LAYER 1: NETWORK, DNS, TRANSPORT & CDN / EDGE / WAF
  // =========================================================================
  const dnsNs = (dns && Array.isArray(dns.nameservers) ? dns.nameservers : []).join(" ").toLowerCase();
  const dnsCname = (dns && dns.cname ? String(dns.cname) : "").toLowerCase();
  const dnsTxt = (dns && Array.isArray(dns.txt) ? dns.txt : []).join(" ").toLowerCase();

  if (dns && dns.ip) {
    reg.addNetworkEvidence({
      id: "EVID-L1-DNS",
      layer: "L1_NETWORK",
      tech: `DNS A-Record (${dns.ip})`,
      rule: "RFC-8484 / Authoritative DNS Resolution",
      detail: `Resolved IP: ${dns.ip}${dns.cname ? ` | CNAME: ${dns.cname}` : ""}${dns.nameservers && dns.nameservers.length ? ` | NS: ${dns.nameservers.slice(0, 2).join(", ")}` : ""}`,
      confidence: "100%"
    });
  }

  const isHttps = protocol === "https:" || (finalUrl && finalUrl.startsWith("https://"));
  if (status > 0 && isHttps) {
    reg.add({
      category: "Security",
      name: "HTTPS / TLS",
      version: null,
      icon: "shield",
      url: "https://developer.mozilla.org/en-US/docs/Glossary/HTTPS",
      confidence: 100,
      layer: "L1_NETWORK",
      rule: "TLS encrypted transport (HTTPS)",
      detail: `Live HTTPS connection established (${finalUrl || `https://${domain}`}, HTTP ${status})`
    });
  }

  if (h["alt-svc"] && /\bh3(?:-29)?=/i.test(h["alt-svc"])) {
    reg.add({
      category: "Network",
      name: "HTTP/3",
      version: null,
      icon: "network",
      url: "https://http3-explained.haxx.se",
      confidence: 100,
      layer: "L1_NETWORK",
      rule: "Header alt-svc advertises h3 (QUIC)",
      detail: `alt-svc: ${h["alt-svc"]}`
    });
  }

  const serverRaw = h["server"] || "";
  const serverLower = serverRaw.toLowerCase();
  const viaLower = (h["via"] || "").toLowerCase();

  // Cloudflare
  if (h["cf-ray"] || serverLower.includes("cloudflare") || hasCookie("__cf_bm") || hasCookie("cf_clearance") || dnsNs.includes("cloudflare")) {
    reg.add({
      category: "CDN",
      name: "Cloudflare",
      version: null,
      icon: "cloudflare",
      url: "https://www.cloudflare.com",
      confidence: 100,
      layer: "L1_NETWORK",
      rule: h["cf-ray"] ? "Header cf-ray" : dnsNs.includes("cloudflare") ? "DNS NS *.cloudflare.com" : "Server/Cookie Cloudflare",
      detail: h["cf-ray"] ? `cf-ray: ${h["cf-ray"]}` : dnsNs.includes("cloudflare") ? `NS: ${dns.nameservers.join(", ")}` : `server: ${serverRaw}`
    });
  }

  // Fastly
  if (h["x-fastly-request-id"] || h["fastly-debug-digest"] || (h["x-served-by"] && /cache-[a-z0-9-]+/i.test(h["x-served-by"])) || dnsCname.includes("fastly")) {
    reg.add({
      category: "CDN",
      name: "Fastly",
      version: null,
      icon: "cloud",
      url: "https://www.fastly.com",
      confidence: 100,
      layer: "L1_NETWORK",
      rule: "Header x-served-by / x-fastly-request-id",
      detail: h["x-served-by"] ? `x-served-by: ${h["x-served-by"]}` : `x-fastly-request-id: ${h["x-fastly-request-id"] || dnsCname}`
    });
  }

  // Amazon CloudFront
  if (h["x-amz-cf-id"] || h["x-amz-cf-pop"] || viaLower.includes("cloudfront") || dnsCname.includes("cloudfront.net")) {
    reg.add({
      category: "CDN",
      name: "Amazon CloudFront",
      version: null,
      icon: "cloud",
      url: "https://aws.amazon.com/cloudfront/",
      confidence: 100,
      layer: "L1_NETWORK",
      rule: "Header x-amz-cf-id / CloudFront edge",
      detail: h["x-amz-cf-id"] ? `x-amz-cf-id: ${h["x-amz-cf-id"]}` : `via/cname: ${h["via"] || dnsCname}`
    });
  }

  // Akamai
  if (h["akamai-grn"] || h["x-akamai-transformed"] || serverLower.includes("akamaighost") || dnsCname.includes("akamai") || dnsCname.includes("edgekey.net") || dnsCname.includes("edgesuite.net")) {
    reg.add({
      category: "CDN",
      name: "Akamai",
      version: null,
      icon: "cloud",
      url: "https://www.akamai.com",
      confidence: 100,
      layer: "L1_NETWORK",
      rule: "Akamai edge header / CNAME",
      detail: h["akamai-grn"] ? `akamai-grn: ${h["akamai-grn"]}` : `server/cname: ${serverRaw || dnsCname}`
    });
  }

  // Vercel
  if (h["x-vercel-id"] || serverLower === "vercel" || dnsCname.includes("vercel-dns.com") || dnsNs.includes("vercel-dns.com")) {
    reg.add({
      category: "PaaS",
      name: "Vercel",
      version: null,
      icon: "vercel",
      url: "https://vercel.com",
      confidence: 100,
      layer: "L1_NETWORK",
      rule: "Header x-vercel-id / Server: Vercel",
      detail: h["x-vercel-id"] ? `x-vercel-id: ${h["x-vercel-id"]}` : `server/dns: ${serverRaw || dnsCname || dnsNs}`
    });
  }

  // Netlify
  if (h["x-nf-request-id"] || serverLower === "netlify" || dnsCname.includes("netlify") || dnsNs.includes("nsone.net") && domain.endsWith(".netlify.app")) {
    reg.add({
      category: "PaaS",
      name: "Netlify",
      version: null,
      icon: "cloud",
      url: "https://www.netlify.com",
      confidence: 100,
      layer: "L1_NETWORK",
      rule: "Header x-nf-request-id / Server: Netlify",
      detail: h["x-nf-request-id"] ? `x-nf-request-id: ${h["x-nf-request-id"]}` : `server: ${serverRaw}`
    });
  }

  // GitHub Pages
  if (serverLower === "github.com" || h["x-github-request-id"] || dnsCname.includes("github.io")) {
    reg.add({
      category: "PaaS",
      name: "GitHub Pages",
      version: null,
      icon: "cloud",
      url: "https://pages.github.com",
      confidence: 100,
      layer: "L1_NETWORK",
      rule: "Header Server: GitHub.com / x-github-request-id",
      detail: h["x-github-request-id"] ? `x-github-request-id: ${h["x-github-request-id"]}` : `server: ${serverRaw}`
    });
  }

  // Azure Front Door / App Service
  if (h["x-azure-ref"] || dnsCname.includes("azurefd.net") || dnsCname.includes("azurewebsites.net")) {
    reg.add({
      category: "PaaS",
      name: "Microsoft Azure",
      version: null,
      icon: "microsoft",
      url: "https://azure.microsoft.com",
      confidence: 100,
      layer: "L1_NETWORK",
      rule: "Header x-azure-ref / Azure CNAME",
      detail: h["x-azure-ref"] ? `x-azure-ref: ${h["x-azure-ref"]}` : `cname: ${dnsCname}`
    });
  }

  // AWS Route 53 / AWS Hosting
  if (dnsNs.includes("awsdns")) {
    reg.add({
      category: "DNS",
      name: "Amazon Route 53",
      version: null,
      icon: "cloud",
      url: "https://aws.amazon.com/route53/",
      confidence: 100,
      layer: "L1_NETWORK",
      rule: "Authoritative NS *.awsdns-*",
      detail: `NS: ${dns.nameservers.slice(0, 2).join(", ")}`
    });
  }
  if (hasCookie("awsalb") || hasCookie("awsalbcors") || serverLower.includes("awselb") || h["x-amzn-requestid"]) {
    reg.add({
      category: "PaaS",
      name: "Amazon Web Services",
      version: null,
      icon: "cloud",
      url: "https://aws.amazon.com",
      confidence: 100,
      layer: "L1_NETWORK",
      rule: "AWS ALB / API Gateway header or cookie",
      detail: h["x-amzn-requestid"] ? `x-amzn-requestid: ${h["x-amzn-requestid"]}` : `server/cookie: ${serverRaw || "AWSALB"}`
    });
  }

  // Google Cloud / GFE
  if (/^(gws|gfe|sffe|esf|google frontend)/i.test(serverRaw) || viaLower.includes("google")) {
    reg.add({
      category: "PaaS",
      name: "Google Cloud",
      version: null,
      icon: "cloud",
      url: "https://cloud.google.com",
      confidence: 95,
      layer: "L1_NETWORK",
      rule: "Google Frontend Server / Via header",
      detail: `server: ${serverRaw || h["via"]}`
    });
  }

  // BunnyCDN
  if (serverLower.includes("bunnycdn") || h["cdn-pullzone"]) {
    reg.add({
      category: "CDN",
      name: "BunnyCDN",
      version: null,
      icon: "cloud",
      url: "https://bunny.net",
      confidence: 100,
      layer: "L1_NETWORK",
      rule: "Header Server: BunnyCDN / cdn-pullzone",
      detail: `server: ${serverRaw || h["cdn-pullzone"]}`
    });
  }

  // Hostinger & hPanel
  if (h["platform"] === "hostinger" || h["panel"] === "hpanel" || dnsNs.includes("dns-parking.com") || dnsNs.includes("hostinger")) {
    reg.add({
      category: "Hosting",
      name: "Hostinger",
      version: null,
      icon: "cloud",
      url: "https://www.hostinger.com",
      confidence: 100,
      layer: "L2_HEADERS",
      rule: "Header platform: hostinger / Hostinger NS",
      detail: h["platform"] ? `platform: ${h["platform"]}` : `NS: ${dns.nameservers.join(", ")}`
    });
    if (h["panel"] === "hpanel") {
      reg.add({
        category: "Hosting panels",
        name: "hPanel",
        version: null,
        icon: "server",
        url: "https://www.hostinger.com/hpanel",
        confidence: 100,
        layer: "L2_HEADERS",
        rule: "Header panel: hpanel",
        detail: `panel: ${h["panel"]}`
      });
    }
  }

  // WAFs: Imperva, Sucuri, F5 BIG-IP
  if (h["x-iinfo"] || hasCookie("visid_incap") || hasCookie("incap_ses")) {
    reg.add({
      category: "Security",
      name: "Imperva",
      version: null,
      icon: "shield",
      url: "https://www.imperva.com",
      confidence: 100,
      layer: "L2_HEADERS",
      rule: "Header x-iinfo / Incapsula cookie",
      detail: h["x-iinfo"] ? `x-iinfo: ${h["x-iinfo"]}` : "Set-Cookie: visid_incap / incap_ses"
    });
  }

  if (h["x-sucuri-id"] || serverLower.includes("sucuri")) {
    reg.add({
      category: "Security",
      name: "Sucuri",
      version: null,
      icon: "shield",
      url: "https://sucuri.net",
      confidence: 100,
      layer: "L2_HEADERS",
      rule: "Header x-sucuri-id / Server: Sucuri",
      detail: h["x-sucuri-id"] ? `x-sucuri-id: ${h["x-sucuri-id"]}` : `server: ${serverRaw}`
    });
  }

  const f5WafBlock = /The requested URL was rejected\.\s*Please consult with your administrator/i.test(html) && /support ID is:/i.test(html);
  if (hasCookie("bigipserver") || /^ts01[a-f0-9]+/i.test(cookieNames.join(" ")) || cookieNames.some((c) => /^ts[0-9a-f]{6,}$/i.test(c)) || h["x-wa-info"] || f5WafBlock) {
    reg.add({
      category: "Security",
      name: "F5 BIG-IP",
      version: f5WafBlock ? "ASM" : null,
      icon: "f5",
      url: "https://www.f5.com",
      confidence: 100,
      layer: f5WafBlock ? "L3_DOM_META" : "L2_HEADERS",
      rule: f5WafBlock ? "F5 BIG-IP ASM Rejection Signature" : "BIGipServer / TS* WAF Cookie",
      detail: f5WafBlock ? "Response body: The requested URL was rejected (F5 ASM Support ID)" : `Cookie/Header match: ${truncateSnippet(cookieJoined || h["x-wa-info"])}`
    });
  }

  // =========================================================================
  // LAYER 2: HTTP HEADERS & COOKIES (Web Servers, Caching, Security, Languages)
  // =========================================================================
  if (serverLower.includes("openresty")) {
    const v = serverRaw.match(/openresty\/([\d.]+)/i)?.[1] || null;
    reg.add({ category: "Web servers", name: "OpenResty", version: v, icon: "nginx", url: "https://openresty.org", confidence: 100, layer: "L2_HEADERS", rule: "Header Server: openresty", detail: `server: ${serverRaw}` });
  } else if (serverLower.includes("nginx")) {
    const v = serverRaw.match(/nginx\/([\d.]+)/i)?.[1] || null;
    reg.add({ category: "Web servers", name: "Nginx", version: v, icon: "nginx", url: "https://nginx.org", confidence: 100, layer: "L2_HEADERS", rule: "Header Server: nginx", detail: `server: ${serverRaw}` });
  } else if (serverLower.includes("litespeed")) {
    const v = serverRaw.match(/litespeed\/([\d.]+)/i)?.[1] || null;
    reg.add({ category: "Web servers", name: "LiteSpeed", version: v, icon: "litespeed", url: "https://www.litespeedtech.com", confidence: 100, layer: "L2_HEADERS", rule: "Header Server: LiteSpeed", detail: `server: ${serverRaw}` });
  } else if (serverLower.includes("apache")) {
    const v = serverRaw.match(/apache\/([\d.]+)/i)?.[1] || null;
    reg.add({ category: "Web servers", name: "Apache", version: v, icon: "apache", url: "https://httpd.apache.org", confidence: 100, layer: "L2_HEADERS", rule: "Header Server: Apache", detail: `server: ${serverRaw}` });
  } else if (serverLower.includes("microsoft-iis")) {
    const v = serverRaw.match(/microsoft-iis\/([\d.]+)/i)?.[1] || null;
    reg.add({ category: "Web servers", name: "Microsoft IIS", version: v, icon: "microsoft", url: "https://www.iis.net", confidence: 100, layer: "L2_HEADERS", rule: "Header Server: Microsoft-IIS", detail: `server: ${serverRaw}` });
  } else if (serverLower.includes("caddy")) {
    reg.add({ category: "Web servers", name: "Caddy", version: null, icon: "server", url: "https://caddyserver.com", confidence: 100, layer: "L2_HEADERS", rule: "Header Server: Caddy", detail: `server: ${serverRaw}` });
  } else if (serverLower.includes("envoy")) {
    reg.add({ category: "Web servers", name: "Envoy", version: null, icon: "server", url: "https://www.envoyproxy.io", confidence: 100, layer: "L2_HEADERS", rule: "Header Server: envoy", detail: `server: ${serverRaw}` });
  } else if (serverLower.includes("gunicorn")) {
    const v = serverRaw.match(/gunicorn\/([\d.]+)/i)?.[1] || null;
    reg.add({ category: "Web servers", name: "Gunicorn", version: v, icon: "python", url: "https://gunicorn.org", confidence: 100, layer: "L2_HEADERS", rule: "Header Server: gunicorn", detail: `server: ${serverRaw}` });
  } else if (serverLower.includes("cowboy")) {
    reg.add({ category: "Web servers", name: "Cowboy", version: null, icon: "server", url: "https://ninenines.eu", confidence: 100, layer: "L2_HEADERS", rule: "Header Server: Cowboy", detail: `server: ${serverRaw}` });
  } else if (serverLower.includes("kestrel")) {
    reg.add({ category: "Web servers", name: "Kestrel", version: null, icon: "microsoft", url: "https://learn.microsoft.com/aspnet/core/fundamentals/servers/kestrel", confidence: 100, layer: "L2_HEADERS", rule: "Header Server: Kestrel", detail: `server: ${serverRaw}` });
  }

  // Varnish & LiteSpeed Cache
  if (h["x-varnish"] || viaLower.includes("varnish")) {
    reg.add({ category: "Caching", name: "Varnish", version: null, icon: "server", url: "https://varnish-cache.org", confidence: 100, layer: "L2_HEADERS", rule: "Header x-varnish / via: varnish", detail: h["x-varnish"] ? `x-varnish: ${h["x-varnish"]}` : `via: ${h["via"]}` });
  }
  if (h["x-litespeed-cache"]) {
    reg.add({ category: "Caching", name: "LiteSpeed Cache", version: null, icon: "litespeed", url: "https://www.litespeedtech.com/products/cache-plugins", confidence: 100, layer: "L2_HEADERS", rule: "Header x-litespeed-cache", detail: `x-litespeed-cache: ${h["x-litespeed-cache"]}` });
  }

  // HSTS
  if (h["strict-transport-security"]) {
    reg.add({ category: "Security", name: "HSTS", version: null, icon: "shield", url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security", confidence: 100, layer: "L2_HEADERS", rule: "Header Strict-Transport-Security", detail: `strict-transport-security: ${h["strict-transport-security"]}` });
  }

  // X-Powered-By & Framework Headers & Cookies
  const xPoweredRaw = h["x-powered-by"] || "";
  const xPoweredLower = xPoweredRaw.toLowerCase();

  if (xPoweredLower.includes("php") || hasCookie("phpsessid")) {
    const v = xPoweredRaw.match(/php\/([\d.]+)/i)?.[1] || null;
    reg.add({
      category: "Programming languages",
      name: "PHP",
      version: v,
      icon: "php",
      url: "https://www.php.net",
      confidence: 100,
      layer: "L2_HEADERS",
      rule: xPoweredLower.includes("php") ? "Header x-powered-by: PHP" : "Cookie PHPSESSID",
      detail: xPoweredLower.includes("php") ? `x-powered-by: ${xPoweredRaw}` : "Set-Cookie: PHPSESSID"
    });
  }

  if (xPoweredLower.includes("asp.net") || h["x-aspnet-version"] || h["x-aspnetmvc-version"] || hasCookie("asp.net_sessionid")) {
    const v = h["x-aspnet-version"] || h["x-aspnetmvc-version"] || null;
    reg.add({
      category: "Web frameworks",
      name: "ASP.NET",
      version: v,
      icon: "microsoft",
      url: "https://dotnet.microsoft.com/apps/aspnet",
      confidence: 100,
      layer: "L2_HEADERS",
      rule: "ASP.NET response header / session cookie",
      detail: h["x-aspnet-version"] ? `x-aspnet-version: ${h["x-aspnet-version"]}` : `x-powered-by/cookie: ${xPoweredRaw || "ASP.NET_SessionId"}`
    });
  }

  if (h["microsoftsharepointteamservices"] || h["x-sharepointhealthscore"] || h["sprequestguid"]) {
    const v = h["microsoftsharepointteamservices"] || null;
    reg.add({
      category: "CMS",
      name: "Microsoft SharePoint",
      version: v,
      icon: "microsoft",
      url: "https://www.microsoft.com/microsoft-365/sharepoint",
      confidence: 100,
      layer: "L2_HEADERS",
      rule: "SharePoint HTTP response header",
      detail: h["microsoftsharepointteamservices"] ? `microsoftsharepointteamservices: ${v}` : `sprequestguid/healthscore present`
    });
  }

  if (xPoweredLower.includes("express")) {
    reg.add({ category: "Web frameworks", name: "Express", version: null, icon: "nodejs", url: "https://expressjs.com", confidence: 100, layer: "L2_HEADERS", rule: "Header x-powered-by: Express", detail: `x-powered-by: ${xPoweredRaw}` });
  }

  if (xPoweredLower.includes("next.js") || h["x-nextjs-cache"] || h["x-nextjs-matched-path"]) {
    reg.add({ category: "Web frameworks", name: "Next.js", version: null, icon: "nextjs", url: "https://nextjs.org", confidence: 100, layer: "L2_HEADERS", rule: "Header x-powered-by: Next.js / x-nextjs-cache", detail: xPoweredRaw ? `x-powered-by: ${xPoweredRaw}` : `x-nextjs-cache: ${h["x-nextjs-cache"]}` });
  }

  if (xPoweredLower.includes("nuxt")) {
    reg.add({ category: "Web frameworks", name: "Nuxt.js", version: null, icon: "nuxt", url: "https://nuxt.com", confidence: 100, layer: "L2_HEADERS", rule: "Header x-powered-by: Nuxt", detail: `x-powered-by: ${xPoweredRaw}` });
  }

  if (hasCookie("laravel_session")) {
    reg.add({ category: "Web frameworks", name: "Laravel", version: null, icon: "php", url: "https://laravel.com", confidence: 100, layer: "L2_HEADERS", rule: "Cookie laravel_session", detail: "Set-Cookie: laravel_session" });
  }

  if (hasCookie("ci_session")) {
    reg.add({ category: "Web frameworks", name: "CodeIgniter", version: null, icon: "php", url: "https://codeigniter.com", confidence: 100, layer: "L2_HEADERS", rule: "Cookie ci_session", detail: "Set-Cookie: ci_session" });
  }

  if (hasCookie("jsessionid") || /servlet|jsp/i.test(xPoweredRaw)) {
    reg.add({ category: "Programming languages", name: "Java", version: null, icon: "code", url: "https://www.java.com", confidence: 95, layer: "L2_HEADERS", rule: "Cookie JSESSIONID / Servlet header", detail: hasCookie("jsessionid") ? "Set-Cookie: JSESSIONID" : `x-powered-by: ${xPoweredRaw}` });
  }

  if (h["x-drupal-cache"] || h["x-drupal-dynamic-cache"] || (h["x-generator"] && /drupal/i.test(h["x-generator"]))) {
    const v = h["x-generator"]?.match(/drupal\s*([\d.]+)/i)?.[1] || null;
    reg.add({ category: "CMS", name: "Drupal", version: v, icon: "drupal", url: "https://www.drupal.org", confidence: 100, layer: "L2_HEADERS", rule: "Header x-drupal-cache / x-generator", detail: h["x-generator"] || `x-drupal-cache: ${h["x-drupal-cache"] || h["x-drupal-dynamic-cache"]}` });
  }

  if ((h["link"] && h["link"].includes("https://api.w.org/")) || (h["x-pingback"] && h["x-pingback"].includes("xmlrpc.php"))) {
    reg.add({ category: "CMS", name: "WordPress", version: null, icon: "wordpress", url: "https://wordpress.org", confidence: 100, layer: "L2_HEADERS", rule: "Header Link: <https://api.w.org/> / x-pingback", detail: truncateSnippet(h["link"] || h["x-pingback"]) });
  }

  if (h["x-shopid"] || h["x-shopify-stage"] || h["x-sorting-hat-shopid"]) {
    reg.add({ category: "Ecommerce", name: "Shopify", version: null, icon: "shopify", url: "https://www.shopify.com", confidence: 100, layer: "L2_HEADERS", rule: "Header x-shopid / x-shopify-stage", detail: `x-shopid: ${h["x-shopid"] || h["x-shopify-stage"]}` });
  }

  if (h["x-wix-request-id"]) {
    reg.add({ category: "CMS", name: "Wix", version: null, icon: "code", url: "https://www.wix.com", confidence: 100, layer: "L2_HEADERS", rule: "Header x-wix-request-id", detail: `x-wix-request-id: ${h["x-wix-request-id"]}` });
  }

  // =========================================================================
  // LAYER 3 & 4: HTML DOM, META TAGS, ASSETS, JS FRAMEWORKS & LIBRARIES
  // =========================================================================
  if (html && html.length > 0) {
    const parsed = parseHtmlSignals(html);
    const { html: srcHtml, htmlLower, metas, scriptSrcs, linkTags, iframeSrcs, assetUrls } = parsed;

    // 3A. Meta Generator Tags (supports multiple generator tags in any attribute order)
    for (const meta of metas) {
      if (meta.name !== "generator" || !meta.content) continue;
      const g = meta.content;

      const wpMatch = g.match(/^WordPress\s*([\d.]+)?/i);
      if (wpMatch) {
        reg.add({ category: "CMS", name: "WordPress", version: wpMatch[1] || null, icon: "wordpress", url: "https://wordpress.org", confidence: 100, layer: "L3_DOM_META", rule: 'meta[name="generator"] WordPress', detail: `<meta name="generator" content="${g}">` });
      }

      const elMatch = g.match(/Elementor\s*([\d.]+)?/i);
      if (elMatch) {
        reg.add({ category: "Page builders", name: "Elementor", version: elMatch[1] || null, icon: "elementor", url: "https://elementor.com", confidence: 100, layer: "L3_DOM_META", rule: 'meta[name="generator"] Elementor', detail: `<meta name="generator" content="${g}">` });
      }

      const wooMatch = g.match(/WooCommerce\s*([\d.]+)?/i);
      if (wooMatch) {
        reg.add({ category: "Ecommerce", name: "WooCommerce", version: wooMatch[1] || null, icon: "woocommerce", url: "https://woocommerce.com", confidence: 100, layer: "L3_DOM_META", rule: 'meta[name="generator"] WooCommerce', detail: `<meta name="generator" content="${g}">` });
      }

      const drupalMatch = g.match(/^Drupal\s*([\d.]+)?/i);
      if (drupalMatch) {
        reg.add({ category: "CMS", name: "Drupal", version: drupalMatch[1] || null, icon: "drupal", url: "https://www.drupal.org", confidence: 100, layer: "L3_DOM_META", rule: 'meta[name="generator"] Drupal', detail: `<meta name="generator" content="${g}">` });
      }

      const joomlaMatch = g.match(/^Joomla!?\s*([\d.]+)?/i);
      if (joomlaMatch) {
        reg.add({ category: "CMS", name: "Joomla", version: joomlaMatch[1] || null, icon: "joomla", url: "https://www.joomla.org", confidence: 100, layer: "L3_DOM_META", rule: 'meta[name="generator"] Joomla', detail: `<meta name="generator" content="${g}">` });
      }

      const ghostMatch = g.match(/^Ghost\s*([\d.]+)?/i);
      if (ghostMatch) {
        reg.add({ category: "CMS", name: "Ghost", version: ghostMatch[1] || null, icon: "code", url: "https://ghost.org", confidence: 100, layer: "L3_DOM_META", rule: 'meta[name="generator"] Ghost', detail: `<meta name="generator" content="${g}">` });
      }

      const hugoMatch = g.match(/^Hugo\s*([\d.]+)?/i);
      if (hugoMatch) {
        reg.add({ category: "Static site generator", name: "Hugo", version: hugoMatch[1] || null, icon: "code", url: "https://gohugo.io", confidence: 100, layer: "L3_DOM_META", rule: 'meta[name="generator"] Hugo', detail: `<meta name="generator" content="${g}">` });
      }

      const jekyllMatch = g.match(/^Jekyll\s*v?([\d.]+)?/i);
      if (jekyllMatch) {
        reg.add({ category: "Static site generator", name: "Jekyll", version: jekyllMatch[1] || null, icon: "code", url: "https://jekyllrb.com", confidence: 100, layer: "L3_DOM_META", rule: 'meta[name="generator"] Jekyll', detail: `<meta name="generator" content="${g}">` });
      }

      const astroMatch = g.match(/^Astro\s*v?([\d.]+)?/i);
      if (astroMatch) {
        reg.add({ category: "Static site generator", name: "Astro", version: astroMatch[1] || null, icon: "code", url: "https://astro.build", confidence: 100, layer: "L3_DOM_META", rule: 'meta[name="generator"] Astro', detail: `<meta name="generator" content="${g}">` });
      }

      const gatsbyMatch = g.match(/^Gatsby\s*([\d.]+)?/i);
      if (gatsbyMatch) {
        reg.add({ category: "Static site generator", name: "Gatsby", version: gatsbyMatch[1] || null, icon: "react", url: "https://www.gatsbyjs.com", confidence: 100, layer: "L3_DOM_META", rule: 'meta[name="generator"] Gatsby', detail: `<meta name="generator" content="${g}">` });
      }

      const docusaurusMatch = g.match(/^Docusaurus\s*v?([\d.]+)?/i);
      if (docusaurusMatch) {
        reg.add({ category: "Documentation", name: "Docusaurus", version: docusaurusMatch[1] || null, icon: "react", url: "https://docusaurus.io", confidence: 100, layer: "L3_DOM_META", rule: 'meta[name="generator"] Docusaurus', detail: `<meta name="generator" content="${g}">` });
      }

      const mediawikiMatch = g.match(/^MediaWiki\s*([\d.]+)?/i);
      if (mediawikiMatch) {
        reg.add({ category: "Wikis", name: "MediaWiki", version: mediawikiMatch[1] || null, icon: "code", url: "https://www.mediawiki.org", confidence: 100, layer: "L3_DOM_META", rule: 'meta[name="generator"] MediaWiki', detail: `<meta name="generator" content="${g}">` });
      }

      const ojsMatch = g.match(/Open Journal Systems\s*([\d.]+)?/i);
      if (ojsMatch) {
        reg.add({ category: "CMS", name: "Open Journal Systems", version: ojsMatch[1] || null, icon: "code", url: "https://pkp.sfu.ca/software/ojs/", confidence: 100, layer: "L3_DOM_META", rule: 'meta[name="generator"] OJS', detail: `<meta name="generator" content="${g}">` });
      }

      if (/WPBakery/i.test(g)) {
        reg.add({ category: "Page builders", name: "WPBakery", version: null, icon: "palette", url: "https://wpbakery.com", confidence: 100, layer: "L3_DOM_META", rule: 'meta[name="generator"] WPBakery', detail: `<meta name="generator" content="${g}">` });
      }
    }

    // 3B. CMS & Platform DOM Paths
    const wpAsset = matchAsset(assetUrls, /\/wp-(?:content|includes)\//i);
    const wpApiLink = linkTags.find((l) => l.rel === "https://api.w.org/");
    if (wpAsset || wpApiLink) {
      // Extract WordPress core version from wp-includes core assets if meta generator was stripped
      const wpCoreVerMatch = srcHtml.match(/wp-includes\/(?:js\/wp-emoji-release\.min\.js|css\/dist\/block-library\/style\.min\.css)\?ver=([\d.]+)/i);
      reg.add({
        category: "CMS",
        name: "WordPress",
        version: wpCoreVerMatch ? wpCoreVerMatch[1] : null,
        icon: "wordpress",
        url: "https://wordpress.org",
        confidence: 100,
        layer: "L3_DOM_META",
        rule: wpAsset ? "Asset path /wp-content/ or /wp-includes/" : 'link[rel="https://api.w.org/"]',
        detail: wpAsset ? `Asset: ${wpAsset.url}` : `REST API link: ${wpApiLink.href}`
      });
    }

    // Elementor
    const elAsset = matchAsset(assetUrls, /\/elementor(?:-pro)?\/assets\/[^\s"'<>]*/i);
    if (elAsset || htmlLower.includes("data-elementor-type") || htmlLower.includes("elementor-widget")) {
      const elVer =
        (elAsset && elAsset.url.match(/[?&]ver=([\d.]+)/i)?.[1]) ||
        srcHtml.match(/elementor(?:-pro)?\/assets\/[^"'>]+?ver=([\d.]+)/i)?.[1] ||
        null;
      reg.add({
        category: "Page builders",
        name: "Elementor",
        version: elVer,
        icon: "elementor",
        url: "https://elementor.com",
        confidence: 100,
        layer: "L3_DOM_META",
        rule: elAsset ? 'Asset path /elementor/assets/' : "DOM attribute data-elementor-type",
        detail: elAsset ? `Asset: ${elAsset.url}` : "Elementor DOM structure detected"
      });
    }

    // Divi & WPBakery & WooCommerce & Yoast
    if (matchAsset(assetUrls, /\/themes\/Divi\//i) || htmlLower.includes("et-boc")) {
      reg.add({ category: "Page builders", name: "Divi", version: null, icon: "palette", url: "https://www.elegantthemes.com/gallery/divi/", confidence: 95, layer: "L3_DOM_META", rule: "Theme path /themes/Divi/ or .et-boc", detail: "Divi theme/builder markup detected" });
    }
    if (matchAsset(assetUrls, /\/js_composer\//i) || htmlLower.includes("wpb_wrapper")) {
      reg.add({ category: "Page builders", name: "WPBakery", version: null, icon: "palette", url: "https://wpbakery.com", confidence: 95, layer: "L3_DOM_META", rule: "Asset /js_composer/ or .wpb_wrapper", detail: "WPBakery Page Builder assets detected" });
    }
    const wooAsset = matchAsset(assetUrls, /\/plugins\/woocommerce\//i);
    if (wooAsset) {
      const wooVer = wooAsset.url.match(/[?&]ver=([\d.]+)/i)?.[1] || null;
      reg.add({ category: "Ecommerce", name: "WooCommerce", version: wooVer, icon: "woocommerce", url: "https://woocommerce.com", confidence: 100, layer: "L3_DOM_META", rule: "Asset path /plugins/woocommerce/", detail: `Asset: ${wooAsset.url}` });
    }
    const yoastComment = srcHtml.match(/Yoast SEO plugin v([\d.]+)/i);
    if (yoastComment || htmlLower.includes("yoast-schema-graph")) {
      reg.add({ category: "SEO", name: "Yoast SEO", version: yoastComment ? yoastComment[1] : null, icon: "code", url: "https://yoast.com", confidence: 100, layer: "L3_DOM_META", rule: "Yoast SEO comment / schema graph", detail: yoastComment ? yoastComment[0] : "script.yoast-schema-graph" });
    }

    // Shopify, Webflow, Wix, Squarespace, Drupal, Moodle
    if (matchAsset(assetUrls, /cdn\.shopify\.com/i) || srcHtml.includes("Shopify.theme")) {
      reg.add({ category: "Ecommerce", name: "Shopify", version: null, icon: "shopify", url: "https://www.shopify.com", confidence: 100, layer: "L3_DOM_META", rule: "cdn.shopify.com / Shopify.theme", detail: "Shopify storefront runtime detected" });
    }
    if (htmlLower.includes("data-wf-site=") || matchAsset(assetUrls, /website-files\.com/i)) {
      reg.add({ category: "CMS", name: "Webflow", version: null, icon: "code", url: "https://webflow.com", confidence: 100, layer: "L3_DOM_META", rule: "DOM data-wf-site / website-files.com", detail: "Webflow site attributes detected" });
    }
    if (matchAsset(assetUrls, /static\.wixstatic\.com/i)) {
      reg.add({ category: "CMS", name: "Wix", version: null, icon: "code", url: "https://www.wix.com", confidence: 100, layer: "L3_DOM_META", rule: "static.wixstatic.com asset", detail: "Wix static CDN assets detected" });
    }
    if (matchAsset(assetUrls, /static1?\.squarespace\.com/i)) {
      reg.add({ category: "CMS", name: "Squarespace", version: null, icon: "code", url: "https://www.squarespace.com", confidence: 100, layer: "L3_DOM_META", rule: "squarespace.com static asset", detail: "Squarespace static CDN assets detected" });
    }
    if (matchAsset(assetUrls, /\/sites\/default\/files\//i) || srcHtml.includes("Drupal.settings") || htmlLower.includes("data-drupal-selector")) {
      reg.add({ category: "CMS", name: "Drupal", version: null, icon: "drupal", url: "https://www.drupal.org", confidence: 100, layer: "L3_DOM_META", rule: "Drupal DOM selector / sites/default/files", detail: "Drupal core path or attribute detected" });
    }
    if (srcHtml.includes("M.cfg") && htmlLower.includes("moodle")) {
      reg.add({ category: "LMS", name: "Moodle", version: null, icon: "code", url: "https://moodle.org", confidence: 100, layer: "L3_DOM_META", rule: "Moodle M.cfg runtime", detail: "Moodle LMS configuration object detected" });
    }

    // Backend DOM Markers (Rails, Django, ASP.NET ViewState)
    const csrfParam = metas.find((mt) => mt.name === "csrf-param" && mt.content === "authenticity_token");
    if (csrfParam) {
      reg.add({ category: "Web frameworks", name: "Ruby on Rails", version: null, icon: "code", url: "https://rubyonrails.org", confidence: 95, layer: "L3_DOM_META", rule: 'meta[name="csrf-param" content="authenticity_token"]', detail: "Rails CSRF authenticity_token meta tag" });
    }
    if (htmlLower.includes('name="csrfmiddlewaretoken"') || htmlLower.includes("name='csrfmiddlewaretoken'")) {
      reg.add({ category: "Web frameworks", name: "Django", version: null, icon: "python", url: "https://www.djangoproject.com", confidence: 95, layer: "L3_DOM_META", rule: 'input[name="csrfmiddlewaretoken"]', detail: "Django CSRF middleware token input" });
    }
    if (srcHtml.includes('id="__VIEWSTATE"') || srcHtml.includes('name="__VIEWSTATE"')) {
      reg.add({ category: "Web frameworks", name: "ASP.NET", version: null, icon: "microsoft", url: "https://dotnet.microsoft.com/apps/aspnet", confidence: 100, layer: "L3_DOM_META", rule: 'input[name="__VIEWSTATE"]', detail: "ASP.NET WebForms __VIEWSTATE hidden field" });
    }

    // 3C. Frontend Frameworks (Next.js, Nuxt.js, React, Vue, Angular, Svelte, Astro, Alpine, HTMX)
    const nextAsset = matchAsset(assetUrls, /\/_next\/static\//i);
    if (nextAsset || srcHtml.includes("__NEXT_DATA__") || metas.some((mt) => mt.name === "next-head-count")) {
      reg.add({
        category: "Web frameworks",
        name: "Next.js",
        version: null,
        icon: "nextjs",
        url: "https://nextjs.org",
        confidence: 100,
        layer: "L4_JS_GLOBALS",
        rule: "DOM __NEXT_DATA__ or /_next/static/ chunks",
        detail: nextAsset ? `Chunk: ${nextAsset.url}` : "Next.js hydration script __NEXT_DATA__ detected"
      });
    }

    const nuxtAsset = matchAsset(assetUrls, /\/_nuxt\//i);
    if (nuxtAsset || srcHtml.includes("__NUXT__") || htmlLower.includes("data-n-head")) {
      reg.add({
        category: "Web frameworks",
        name: "Nuxt.js",
        version: null,
        icon: "nuxt",
        url: "https://nuxt.com",
        confidence: 100,
        layer: "L4_JS_GLOBALS",
        rule: "DOM __NUXT__ or /_nuxt/ chunks",
        detail: nuxtAsset ? `Chunk: ${nuxtAsset.url}` : "Nuxt.js SSR payload __NUXT__ detected"
      });
    }

    const reactAsset = matchAsset(scriptSrcs, /react(?:-dom)?(?:[.-]([\d.]+))?(?:\.production)?(?:\.min)?\.js/i);
    if (reactAsset || htmlLower.includes("data-reactroot") || htmlLower.includes("data-reactid")) {
      reg.add({
        category: "JavaScript frameworks",
        name: "React",
        version: reactAsset?.match?.[1] || null,
        icon: "react",
        url: "https://react.dev",
        confidence: 100,
        layer: "L4_JS_GLOBALS",
        rule: reactAsset ? "Script react/react-dom" : "DOM data-reactroot",
        detail: reactAsset ? `Script: ${reactAsset.url}` : "React SSR root attribute detected"
      });
    }

    const vueAsset = matchAsset(scriptSrcs, /vue(?:\.runtime)?(?:\.global)?(?:[.-]([\d.]+))?(?:\.prod)?(?:\.min)?\.js/i);
    const vueScopedMatch = srcHtml.match(/\bdata-v-[a-f0-9]{6,8}\b/);
    if (vueAsset || vueScopedMatch || srcHtml.includes("__VUE__")) {
      reg.add({
        category: "JavaScript frameworks",
        name: "Vue.js",
        version: vueAsset?.match?.[1] || null,
        icon: "vue",
        url: "https://vuejs.org",
        confidence: 100,
        layer: "L4_JS_GLOBALS",
        rule: vueAsset ? "Script vue.js" : "Scoped CSS attribute data-v-*",
        detail: vueAsset ? `Script: ${vueAsset.url}` : `Attribute: ${vueScopedMatch ? vueScopedMatch[0] : "__VUE__"}`
      });
    }

    const ngVerMatch = srcHtml.match(/\bng-version\s*=\s*["']([\d.]+)["']/i);
    if (ngVerMatch || /\bng-app\s*=/.test(srcHtml)) {
      reg.add({
        category: "JavaScript frameworks",
        name: "Angular",
        version: ngVerMatch ? ngVerMatch[1] : null,
        icon: "code",
        url: "https://angular.dev",
        confidence: 100,
        layer: "L4_JS_GLOBALS",
        rule: 'DOM attribute ng-version / ng-app',
        detail: ngVerMatch ? ngVerMatch[0] : "Angular ng-app directive detected"
      });
    }

    if (srcHtml.includes("__sveltekit") || /class=["'][^"']*\bsvelte-[a-z0-9]{5,}\b/.test(srcHtml)) {
      reg.add({ category: "JavaScript frameworks", name: "Svelte", version: null, icon: "code", url: "https://svelte.dev", confidence: 95, layer: "L4_JS_GLOBALS", rule: "SvelteKit runtime / svelte-* hash classes", detail: "Svelte compiled DOM signature detected" });
    }

    if (htmlLower.includes("<astro-island") || htmlLower.includes("data-astro-cid-")) {
      reg.add({ category: "Static site generator", name: "Astro", version: null, icon: "code", url: "https://astro.build", confidence: 100, layer: "L3_DOM_META", rule: "Element <astro-island> / data-astro-cid", detail: "Astro island architecture markup detected" });
    }

    const alpineAsset = matchAsset(scriptSrcs, /alpine(?:js)?(?:[@/.-]([\d.]+))?/i);
    if (alpineAsset || (/\bx-data\s*=/.test(srcHtml) && /\b(?:x-show|x-on:|x-bind:|x-text)\b/.test(srcHtml))) {
      reg.add({ category: "JavaScript frameworks", name: "Alpine.js", version: alpineAsset?.match?.[1] || null, icon: "code", url: "https://alpinejs.dev", confidence: 95, layer: "L4_JS_GLOBALS", rule: "Alpine.js script or x-data directives", detail: alpineAsset ? `Script: ${alpineAsset.url}` : "Alpine x-data + directive attributes" });
    }

    const htmxAsset = matchAsset(scriptSrcs, /htmx(?:\.min)?\.js/i);
    if (htmxAsset || (/\bhx-(?:get|post|swap|target)\s*=/.test(srcHtml))) {
      reg.add({ category: "JavaScript libraries", name: "htmx", version: null, icon: "code", url: "https://htmx.org", confidence: 95, layer: "L4_JS_GLOBALS", rule: "htmx.js or hx-* attributes", detail: htmxAsset ? `Script: ${htmxAsset.url}` : "htmx declarative attributes detected" });
    }

    // 3D. JavaScript Libraries (carefully disambiguated so jquery-ui / jquery-migrate don't corrupt core jQuery version)
    const jqCoreAsset = matchAsset(scriptSrcs, /(?:^|\/)jquery(?:[.-]([\d.]+))?(?:\.slim)?(?:\.min)?\.js(?:\?[^"']*?ver=([\d.]+))?/i);
    if (jqCoreAsset) {
      const ver = jqCoreAsset.match[1] || jqCoreAsset.match[2] || null;
      reg.add({
        category: "JavaScript libraries",
        name: "jQuery",
        version: ver,
        icon: "jquery",
        url: "https://jquery.com",
        confidence: 100,
        layer: "L4_JS_GLOBALS",
        rule: 'script[src*="jquery.js"]',
        detail: `Script: ${jqCoreAsset.url}`
      });
    }

    const jqUiAsset = matchAsset(assetUrls, /jquery[.-]ui(?:[.-]([\d.]+))?[^"']*(?:[?&]ver=([\d.]+))?|\/jquery\/ui\/core(?:\.min)?\.js(?:\?[^"']*?ver=([\d.]+))?/i);
    if (jqUiAsset) {
      const ver = jqUiAsset.match[1] || jqUiAsset.match[2] || jqUiAsset.match[3] || null;
      reg.add({
        category: "JavaScript libraries",
        name: "jQuery UI",
        version: ver,
        icon: "jquery-ui",
        url: "https://jqueryui.com",
        confidence: 100,
        layer: "L4_JS_GLOBALS",
        rule: 'Asset jquery-ui / jquery/ui/core',
        detail: `Asset: ${jqUiAsset.url}`
      });
    }

    const jqMigAsset = matchAsset(scriptSrcs, /jquery[.-]migrate(?:[.-]([\d.]+))?(?:\.min)?\.js(?:\?[^"']*?ver=([\d.]+))?/i);
    if (jqMigAsset) {
      const ver = jqMigAsset.match[1] || jqMigAsset.match[2] || null;
      reg.add({
        category: "JavaScript libraries",
        name: "jQuery Migrate",
        version: ver,
        icon: "jquery-migrate",
        url: "https://github.com/jquery/jquery-migrate",
        confidence: 100,
        layer: "L4_JS_GLOBALS",
        rule: 'script[src*="jquery-migrate"]',
        detail: `Script: ${jqMigAsset.url}`
      });
    }

    const select2Asset = matchAsset(assetUrls, /select2(?:[.-]([\d.]+))?(?:\.full)?(?:\.min)?\.(?:js|css)(?:\?[^"']*?ver=([\d.]+))?/i);
    if (select2Asset) {
      const ver = select2Asset.match[1] || select2Asset.match[2] || null;
      reg.add({
        category: "JavaScript libraries",
        name: ".Select2",
        version: ver,
        icon: "select2",
        url: "https://select2.org",
        confidence: 100,
        layer: "L4_JS_GLOBALS",
        rule: 'Asset select2.(js|css)',
        detail: `Asset: ${select2Asset.url}`
      });
    }

    const masonryAsset = matchAsset(scriptSrcs, /masonry(?:\.pkgd)?(?:[.-]([\d.]+))?(?:\.min)?\.js(?:\?[^"']*?ver=([\d.]+))?/i);
    if (masonryAsset) {
      const ver = masonryAsset.match[1] || masonryAsset.match[2] || null;
      reg.add({
        category: "JavaScript libraries",
        name: "Masonry",
        version: ver,
        icon: "masonry",
        url: "https://masonry.desandro.com",
        confidence: 100,
        layer: "L4_JS_GLOBALS",
        rule: 'script[src*="masonry"]',
        detail: `Script: ${masonryAsset.url}`
      });
    }

    const swiperAsset = matchAsset(assetUrls, /swiper(?:-bundle)?(?:[/@.-]([\d.]+))?[^"']*\.(?:js|css)/i);
    if (swiperAsset) {
      const ver = swiperAsset.match[1] || extractAssetVersion(swiperAsset.url, "swiper");
      reg.add({ category: "JavaScript libraries", name: "Swiper", version: ver, icon: "code", url: "https://swiperjs.com", confidence: 100, layer: "L4_JS_GLOBALS", rule: 'Asset swiper.(js|css)', detail: `Asset: ${swiperAsset.url}` });
    }

    const slickAsset = matchAsset(assetUrls, /slick(?:-carousel)?[^"']*\.(?:js|css)/i);
    if (slickAsset) {
      const ver = extractAssetVersion(slickAsset.url, "slick(?:-carousel)?");
      reg.add({ category: "JavaScript libraries", name: "Slick", version: ver, icon: "code", url: "https://kenwheeler.github.io/slick/", confidence: 100, layer: "L4_JS_GLOBALS", rule: 'Asset slick.(js|css)', detail: `Asset: ${slickAsset.url}` });
    }

    const owlAsset = matchAsset(assetUrls, /owl\.carousel[^"']*\.(?:js|css)/i);
    if (owlAsset) {
      const ver = extractAssetVersion(owlAsset.url, "owl\\.?carousel2?");
      reg.add({ category: "JavaScript libraries", name: "Owl Carousel", version: ver, icon: "code", url: "https://owlcarousel2.github.io/OwlCarousel2/", confidence: 100, layer: "L4_JS_GLOBALS", rule: 'Asset owl.carousel', detail: `Asset: ${owlAsset.url}` });
    }

    const dtAsset = matchAsset(assetUrls, /(?:jquery\.)?dataTables(?:[/@.-]([\d.]+))?[^"']*\.(?:js|css)/i);
    if (dtAsset) {
      const ver = dtAsset.match[1] || extractAssetVersion(dtAsset.url, "datatables(?:\\.net)?");
      reg.add({ category: "JavaScript libraries", name: "DataTables", version: ver, icon: "code", url: "https://datatables.net", confidence: 100, layer: "L4_JS_GLOBALS", rule: 'Asset dataTables', detail: `Asset: ${dtAsset.url}` });
    }

    const lodashAsset = matchAsset(scriptSrcs, /lodash(?:[/@.-]([\d.]+))?[^"']*\.js/i);
    if (lodashAsset) {
      const ver = lodashAsset.match[1] || extractAssetVersion(lodashAsset.url, "lodash(?:\\.js)?");
      reg.add({ category: "JavaScript libraries", name: "Lodash", version: ver, icon: "code", url: "https://lodash.com", confidence: 100, layer: "L4_JS_GLOBALS", rule: 'script[src*="lodash"]', detail: `Script: ${lodashAsset.url}` });
    }

    const gsapAsset = matchAsset(scriptSrcs, /gsap(?:[/@.-]([\d.]+))?[^"']*\.js/i);
    if (gsapAsset) {
      const ver = gsapAsset.match[1] || extractAssetVersion(gsapAsset.url, "gsap");
      reg.add({ category: "JavaScript libraries", name: "GSAP", version: ver, icon: "code", url: "https://gsap.com", confidence: 100, layer: "L4_JS_GLOBALS", rule: 'script[src*="gsap"]', detail: `Script: ${gsapAsset.url}` });
    }

    const chartAsset = matchAsset(scriptSrcs, /chart(?:\.umd)?(?:[/@.-]([\d.]+))?[^"']*\.js/i);
    if (chartAsset) {
      const ver = chartAsset.match[1] || extractAssetVersion(chartAsset.url, "chart\\.?js");
      reg.add({ category: "JavaScript graphics", name: "Chart.js", version: ver, icon: "code", url: "https://www.chartjs.org", confidence: 95, layer: "L4_JS_GLOBALS", rule: 'script[src*="chart.js"]', detail: `Script: ${chartAsset.url}` });
    }

    const axiosAsset = matchAsset(scriptSrcs, /axios(?:[/@.-]([\d.]+))?[^"']*\.js/i);
    if (axiosAsset) {
      const ver = axiosAsset.match[1] || extractAssetVersion(axiosAsset.url, "axios");
      reg.add({ category: "JavaScript libraries", name: "Axios", version: ver, icon: "code", url: "https://axios-http.com", confidence: 100, layer: "L4_JS_GLOBALS", rule: 'script[src*="axios"]', detail: `Script: ${axiosAsset.url}` });
    }

    const sweetAlertAsset = matchAsset(assetUrls, /sweetalert2(?:[/@.-]([\d.]+))?/i);
    if (sweetAlertAsset) {
      const ver = sweetAlertAsset.match[1] || extractAssetVersion(sweetAlertAsset.url, "sweetalert2");
      reg.add({ category: "JavaScript libraries", name: "SweetAlert2", version: ver, icon: "code", url: "https://sweetalert2.github.io", confidence: 100, layer: "L4_JS_GLOBALS", rule: 'Asset sweetalert2', detail: `Asset: ${sweetAlertAsset.url}` });
    }

    const aosAsset = matchAsset(assetUrls, /(?:^|\/)aos(?:[/@.-]([\d.]+))?[^"']*\.(?:js|css)/i);
    if (aosAsset) {
      const ver = aosAsset.match[1] || extractAssetVersion(aosAsset.url, "aos");
      reg.add({ category: "JavaScript libraries", name: "AOS", version: ver, icon: "code", url: "https://michalsnik.github.io/aos/", confidence: 100, layer: "L4_JS_GLOBALS", rule: 'Asset aos.(js|css)', detail: `Asset: ${aosAsset.url}` });
    }

    const momentAsset = matchAsset(scriptSrcs, /moment(?:[/@.-]([\d.]+))?[^"']*\.js/i);
    if (momentAsset) {
      const ver = momentAsset.match[1] || extractAssetVersion(momentAsset.url, "moment(?:\\.js)?");
      reg.add({ category: "JavaScript libraries", name: "Moment.js", version: ver, icon: "code", url: "https://momentjs.com", confidence: 100, layer: "L4_JS_GLOBALS", rule: 'script[src*="moment"]', detail: `Script: ${momentAsset.url}` });
    }

    const threeAsset = matchAsset(scriptSrcs, /three(?:[/@.-]([\d.]+))?[^"']*\.js/i);
    if (threeAsset) {
      const ver = threeAsset.match[1] || extractAssetVersion(threeAsset.url, "three(?:\\.js)?");
      reg.add({ category: "JavaScript graphics", name: "Three.js", version: ver, icon: "code", url: "https://threejs.org", confidence: 100, layer: "L4_JS_GLOBALS", rule: 'script[src*="three"]', detail: `Script: ${threeAsset.url}` });
    }

    const d3Asset = matchAsset(scriptSrcs, /(?:^|\/)d3(?:[/@.-]([\d.]+))?(?:\.min)?\.js/i);
    if (d3Asset) {
      const ver = d3Asset.match[1] || extractAssetVersion(d3Asset.url, "d3");
      reg.add({ category: "JavaScript graphics", name: "D3", version: ver, icon: "code", url: "https://d3js.org", confidence: 100, layer: "L4_JS_GLOBALS", rule: 'script[src*="d3.js"]', detail: `Script: ${d3Asset.url}` });
    }

    const viteAsset = matchAsset(assetUrls, /\/@vite\/client|vite\/preload-helper/i);
    if (viteAsset) {
      reg.add({ category: "Build tools", name: "Vite", version: null, icon: "code", url: "https://vite.dev", confidence: 100, layer: "L4_JS_GLOBALS", rule: 'Asset /@vite/client', detail: `Asset: ${viteAsset.url}` });
    }

    if (srcHtml.includes("webpackChunk") || srcHtml.includes("webpackJsonp")) {
      reg.add({ category: "Build tools", name: "webpack", version: null, icon: "code", url: "https://webpack.js.org", confidence: 95, layer: "L4_JS_GLOBALS", rule: "Global webpackChunk / webpackJsonp", detail: "Webpack runtime chunk loader detected in inline script" });
    }

    if (srcHtml.includes("wire:id=") && srcHtml.includes("wire:initial-data")) {
      reg.add({ category: "Web frameworks", name: "Laravel Livewire", version: null, icon: "php", url: "https://livewire.laravel.com", confidence: 100, layer: "L3_DOM_META", rule: "DOM attributes wire:id + wire:initial-data", detail: "Laravel Livewire component markers detected" });
    }

    if (srcHtml.includes("data-page=") && htmlLower.includes('id="app"')) {
      reg.add({ category: "Web frameworks", name: "Inertia.js", version: null, icon: "code", url: "https://inertiajs.com", confidence: 90, layer: "L3_DOM_META", rule: 'DOM #app[data-page]', detail: "Inertia.js page payload attribute detected" });
    }

    if (linkTags.some((l) => l.rel === "manifest")) {
      reg.add({ category: "Miscellaneous", name: "PWA", version: null, icon: "network", url: "https://web.dev/progressive-web-apps/", confidence: 95, layer: "L3_DOM_META", rule: 'link[rel="manifest"]', detail: "Web App Manifest linked in document head" });
    }

    if (metas.some((mt) => mt.property === "og:title" || mt.property === "og:type")) {
      reg.add({ category: "Miscellaneous", name: "Open Graph", version: null, icon: "network", url: "https://ogp.me", confidence: 100, layer: "L3_DOM_META", rule: 'meta[property^="og:"]', detail: "Open Graph social metadata protocol detected" });
    }

    if (htmlLower.includes('type="application/ld+json"') || htmlLower.includes("type='application/ld+json'")) {
      reg.add({ category: "SEO", name: "Schema.org (JSON-LD)", version: null, icon: "code", url: "https://schema.org", confidence: 100, layer: "L3_DOM_META", rule: 'script[type="application/ld+json"]', detail: "Structured JSON-LD linked data block detected" });
    }

    // 3E. UI Frameworks & Fonts (strict rules to avoid false positives)
    const bsAsset = matchAsset(assetUrls, /bootstrap(?:[/@.-]([\d.]+))?[^"']*(?:\.bundle)?(?:\.min)?\.(?:js|css)(?:\?[^"']*?ver=([\d.]+))?/i);
    if (bsAsset || /\bdata-bs-(?:toggle|target|dismiss)\s*=/.test(srcHtml)) {
      const bsVer = bsAsset ? (bsAsset.match[1] || bsAsset.match[2] || extractAssetVersion(bsAsset.url, "bootstrap")) : null;
      reg.add({
        category: "UI frameworks",
        name: "Bootstrap",
        version: bsVer,
        icon: "bootstrap",
        url: "https://getbootstrap.com",
        confidence: 100,
        layer: "L3_DOM_META",
        rule: bsAsset ? 'Asset bootstrap.(css|js)' : "Bootstrap 5 data-bs-* attributes",
        detail: bsAsset ? `Asset: ${bsAsset.url}` : "DOM attributes data-bs-toggle/target"
      });
    }

    // Strict Tailwind CSS detection (requires explicit tailwind asset, --tw- CSS vars, OR >= 3 distinct multi-token Tailwind patterns)
    const twAsset = matchAsset(assetUrls, /tailwind(?:css)?(?:\.min)?\.css|cdn\.tailwindcss\.com/i);
    const hasTwCssVar = /--tw-(?:ring-inset|translate-x|bg-opacity|border-spacing|shadow)\b/.test(srcHtml);
    const twSignals = [
      /\b(?:sm|md|lg|xl|2xl):(?:flex|grid|block|hidden|px-\d|py-\d|text-|w-|p-\d)/,
      /\bbg-(?:slate|gray|zinc|neutral|stone|red|orange|amber|yellow|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|pink)-(?:50|[1-9]00)\b/,
      /\btext-(?:slate|gray|zinc|neutral|stone|red|blue|indigo|purple)-(?:50|[1-9]00)\b/,
      /\bspace-[xy]-(?:\d+|px)\b/,
      /\b(?:px|py)-(?:\d+|0\.5|1\.5|2\.5)\b/,
      /\brounded-(?:sm|md|lg|xl|2xl|full)\b/
    ];
    const twMatchCount = twSignals.reduce((acc, rx) => acc + (rx.test(srcHtml) ? 1 : 0), 0);
    if (twAsset || hasTwCssVar || twMatchCount >= 3) {
      reg.add({
        category: "UI frameworks",
        name: "Tailwind CSS",
        version: null,
        icon: "tailwind",
        url: "https://tailwindcss.com",
        confidence: twAsset || hasTwCssVar ? 100 : 90,
        layer: "L3_DOM_META",
        rule: twAsset ? "Tailwind stylesheet/CDN" : hasTwCssVar ? "CSS custom properties --tw-*" : `Multi-token Tailwind utility classes (${twMatchCount}/6 signals)`,
        detail: twAsset ? `Asset: ${twAsset.url}` : hasTwCssVar ? "Inline CSS variables --tw-* detected" : "Distinctive responsive/color Tailwind utility classes in DOM"
      });
    }

    if (htmlLower.includes("v-application") && htmlLower.includes("v-main")) {
      reg.add({ category: "UI frameworks", name: "Vuetify", version: null, icon: "vue", url: "https://vuetifyjs.com", confidence: 95, layer: "L3_DOM_META", rule: "DOM classes .v-application + .v-main", detail: "Vuetify layout classes detected" });
    }
    if (srcHtml.includes("MuiBox-root") || srcHtml.includes("MuiTypography-root") || srcHtml.includes("MuiButton-root")) {
      reg.add({ category: "UI frameworks", name: "MUI", version: null, icon: "react", url: "https://mui.com", confidence: 100, layer: "L3_DOM_META", rule: "DOM classes .Mui*-root", detail: "Material UI runtime classes detected" });
    }
    if (matchAsset(assetUrls, /primer/i) && htmlLower.includes("data-color-mode")) {
      reg.add({ category: "UI frameworks", name: "Primer CSS", version: null, icon: "palette", url: "https://primer.style", confidence: 95, layer: "L3_DOM_META", rule: "Primer stylesheet + data-color-mode", detail: "GitHub Primer design system detected" });
    }

    // Font Scripts
    const faAsset = matchAsset(assetUrls, /(?:font-?awesome|use\.fontawesome\.com|kit\.fontawesome\.com)(?:[/@.-]([\d.]+))?[^"']*(?:[?&]ver=([\d.]+))?/i);
    if (faAsset || /\bclass=["'][^"']*\b(?:fa-solid|fa-regular|fa-brands|fas fa-|fab fa-|far fa-)\b/.test(srcHtml)) {
      const faVer = faAsset ? (faAsset.match[1] || faAsset.match[2] || extractAssetVersion(faAsset.url, "font-?awesome")) : null;
      reg.add({
        category: "Font scripts",
        name: "Font Awesome",
        version: faVer,
        icon: "font-awesome",
        url: "https://fontawesome.com",
        confidence: 100,
        layer: "L3_DOM_META",
        rule: faAsset ? 'Asset font-awesome / fontawesome' : "DOM classes fa-solid / fas fa-",
        detail: faAsset ? `Asset: ${faAsset.url}` : "Font Awesome icon classes detected"
      });
    }

    const bsIconsAsset = matchAsset(assetUrls, /bootstrap-icons(?:[/@.-]([\d.]+))?/i);
    if (bsIconsAsset) {
      reg.add({ category: "Font scripts", name: "Bootstrap Icons", version: bsIconsAsset.match[1] || extractAssetVersion(bsIconsAsset.url, "bootstrap-icons"), icon: "bootstrap", url: "https://icons.getbootstrap.com", confidence: 100, layer: "L3_DOM_META", rule: 'Asset bootstrap-icons', detail: `Asset: ${bsIconsAsset.url}` });
    }

    const gFontAsset = matchAsset(assetUrls, /fonts\.googleapis\.com\/css|fonts\.gstatic\.com/i);
    if (gFontAsset) {
      reg.add({ category: "Font scripts", name: "Google Font API", version: null, icon: "font-awesome", url: "https://fonts.google.com", confidence: 100, layer: "L3_DOM_META", rule: 'link[href*="fonts.googleapis.com"]', detail: `Asset: ${gFontAsset.url}` });
    }

    const typekitAsset = matchAsset(assetUrls, /use\.typekit\.net/i);
    if (typekitAsset) {
      reg.add({ category: "Font scripts", name: "Adobe Fonts", version: null, icon: "font-awesome", url: "https://fonts.adobe.com", confidence: 100, layer: "L3_DOM_META", rule: 'Asset use.typekit.net', detail: `Asset: ${typekitAsset.url}` });
    }

    // Public JS/CSS Asset CDNs (jsDelivr, cdnjs, unpkg)
    const jsdelivrAsset = matchAsset(assetUrls, /cdn\.jsdelivr\.net\//i);
    if (jsdelivrAsset) {
      reg.add({ category: "CDN", name: "jsDelivr", version: null, icon: "cloud", url: "https://www.jsdelivr.com", confidence: 100, layer: "L3_DOM_META", rule: 'Asset cdn.jsdelivr.net', detail: `Asset: ${jsdelivrAsset.url}` });
    }
    const cdnjsAsset = matchAsset(assetUrls, /cdnjs\.cloudflare\.com\//i);
    if (cdnjsAsset) {
      reg.add({ category: "CDN", name: "cdnjs", version: null, icon: "cloudflare", url: "https://cdnjs.com", confidence: 100, layer: "L3_DOM_META", rule: 'Asset cdnjs.cloudflare.com', detail: `Asset: ${cdnjsAsset.url}` });
    }
    const unpkgAsset = matchAsset(assetUrls, /unpkg\.com\//i);
    if (unpkgAsset) {
      reg.add({ category: "CDN", name: "unpkg", version: null, icon: "cloud", url: "https://unpkg.com", confidence: 100, layer: "L3_DOM_META", rule: 'Asset unpkg.com', detail: `Asset: ${unpkgAsset.url}` });
    }

    // 3F. Video Players & Maps
    const ytEmbed = iframeSrcs.find((u) => /youtube(?:-nocookie)?\.com\/embed|youtu\.be/i.test(u)) || scriptSrcs.find((u) => /youtube\.com\/iframe_api/i.test(u));
    if (ytEmbed || /youtube(?:-nocookie)?\.com\/embed\//i.test(srcHtml)) {
      reg.add({
        category: "Video players",
        name: "YouTube",
        version: null,
        icon: "youtube",
        url: "https://www.youtube.com",
        confidence: 100,
        layer: "L3_DOM_META",
        rule: 'iframe[src*="youtube.com/embed"] / iframe_api',
        detail: ytEmbed ? `Embed: ${ytEmbed}` : "YouTube embedded player detected"
      });
    }

    if (iframeSrcs.some((u) => /player\.vimeo\.com/i.test(u))) {
      reg.add({ category: "Video players", name: "Vimeo", version: null, icon: "code", url: "https://vimeo.com", confidence: 100, layer: "L3_DOM_META", rule: 'iframe[src*="player.vimeo.com"]', detail: "Vimeo embedded video player detected" });
    }

    const gMapsAsset = matchAsset(scriptSrcs, /maps\.googleapis\.com\/maps\/api/i);
    const gMapsIframe = iframeSrcs.find((u) => /google\.com\/maps\/embed|maps\.google\.com/i.test(u));
    if (gMapsAsset || gMapsIframe || /maps\.googleapis\.com\/maps\/api/i.test(srcHtml)) {
      reg.add({
        category: "Maps",
        name: "Google Maps",
        version: null,
        icon: "google-maps",
        url: "https://maps.google.com",
        confidence: 100,
        layer: "L3_DOM_META",
        rule: gMapsAsset ? 'script[src*="maps.googleapis.com"]' : 'iframe[src*="google.com/maps"]',
        detail: gMapsAsset ? `Script: ${gMapsAsset.url}` : gMapsIframe ? `Iframe: ${gMapsIframe}` : "Google Maps JS API reference detected"
      });
    }

    const leafletAsset = matchAsset(assetUrls, /leaflet(?:[/@.-]([\d.]+))?[^"']*\.(?:js|css)/i);
    if (leafletAsset) {
      reg.add({ category: "Maps", name: "Leaflet", version: leafletAsset.match[1] || null, icon: "google-maps", url: "https://leafletjs.com", confidence: 100, layer: "L4_JS_GLOBALS", rule: 'Asset leaflet.(js|css)', detail: `Asset: ${leafletAsset.url}` });
    }

    // 3G. Analytics, Tag Managers, Payments & Security Widgets (STRICT regex — zero false positives!)
    const gtagAsset = matchAsset(scriptSrcs, /googletagmanager\.com\/gtag\/js\?[^"']*id=(G-[A-Z0-9]{6,12}|UA-\d+-\d+)/i);
    const ga4IdMatch = srcHtml.match(/['"](G-[A-Z0-9]{7,12})['"]/);
    const gaUaAsset = matchAsset(scriptSrcs, /google-analytics\.com\/(?:analytics|ga)\.js/i);
    const gaUaIdMatch = srcHtml.match(/['"](UA-\d{4,10}-\d{1,4})['"]/);

    if (gtagAsset || ga4IdMatch || gaUaAsset || gaUaIdMatch) {
      const isGa4 = Boolean((gtagAsset && gtagAsset.match[1].startsWith("G-")) || ga4IdMatch);
      const idStr = gtagAsset?.match?.[1] || ga4IdMatch?.[1] || gaUaIdMatch?.[1] || "analytics.js";
      reg.add({
        category: "Analytics",
        name: "Google Analytics",
        version: isGa4 ? "GA4" : "UA",
        icon: "google-analytics",
        url: "https://analytics.google.com",
        confidence: 100,
        layer: "L3_DOM_META",
        rule: isGa4 ? "gtag/js / GA4 measurement ID (G-*)" : "analytics.js / UA property ID",
        detail: `Measurement target: ${idStr}`
      });
    }

    const gtmAsset = matchAsset(scriptSrcs, /googletagmanager\.com\/gtm\.js\?[^"']*id=(GTM-[A-Z0-9]{5,10})/i);
    const gtmInline = srcHtml.match(/['"](GTM-[A-Z0-9]{5,10})['"]/);
    if (gtmAsset || gtmInline) {
      reg.add({
        category: "Tag managers",
        name: "Google Tag Manager",
        version: null,
        icon: "gtm",
        url: "https://tagmanager.google.com",
        confidence: 100,
        layer: "L3_DOM_META",
        rule: "Google Tag Manager container (GTM-*)",
        detail: `Container ID: ${gtmAsset?.match?.[1] || gtmInline?.[1]}`
      });
    }

    if (matchAsset(scriptSrcs, /connect\.facebook\.net\/[^"']*fbevents\.js/i) || /fbq\(\s*['"]init['"]/i.test(srcHtml)) {
      reg.add({ category: "Analytics", name: "Meta Pixel", version: null, icon: "meta", url: "https://developers.facebook.com/docs/meta-pixel/", confidence: 100, layer: "L3_DOM_META", rule: "connect.facebook.net/fbevents.js / fbq('init')", detail: "Meta Pixel tracking script detected" });
    }
    if (matchAsset(scriptSrcs, /clarity\.ms\/tag\//i) || /clarity\.ms\/tag\//i.test(srcHtml)) {
      reg.add({ category: "Analytics", name: "Microsoft Clarity", version: null, icon: "microsoft", url: "https://clarity.microsoft.com", confidence: 100, layer: "L3_DOM_META", rule: "clarity.ms/tag/ script", detail: "Microsoft Clarity session analytics detected" });
    }
    if (matchAsset(scriptSrcs, /static\.hotjar\.com/i) || /static\.hotjar\.com/i.test(srcHtml)) {
      reg.add({ category: "Analytics", name: "Hotjar", version: null, icon: "google-analytics", url: "https://www.hotjar.com", confidence: 100, layer: "L3_DOM_META", rule: "static.hotjar.com script", detail: "Hotjar analytics snippet detected" });
    }
    if (matchAsset(scriptSrcs, /static\.cloudflareinsights\.com\/beacon\.min\.js/i)) {
      reg.add({ category: "Analytics", name: "Cloudflare Browser Insights", version: null, icon: "cloudflare", url: "https://www.cloudflare.com/web-analytics/", confidence: 100, layer: "L3_DOM_META", rule: "cloudflareinsights.com/beacon.min.js", detail: "Cloudflare Web Analytics beacon detected" });
    }
    if (matchAsset(scriptSrcs, /plausible\.io\/js\//i)) {
      reg.add({ category: "Analytics", name: "Plausible", version: null, icon: "google-analytics", url: "https://plausible.io", confidence: 100, layer: "L3_DOM_META", rule: "plausible.io/js/ script", detail: "Plausible analytics script detected" });
    }
    if (matchAsset(scriptSrcs, /browser\.sentry-cdn\.com/i) || /sentry\.io\/\d+/i.test(srcHtml)) {
      reg.add({ category: "Issue trackers", name: "Sentry", version: null, icon: "shield", url: "https://sentry.io", confidence: 100, layer: "L4_JS_GLOBALS", rule: "Sentry SDK / DSN reference", detail: "Sentry error tracking detected" });
    }
    if (matchAsset(scriptSrcs, /js\.stripe\.com\/v3/i)) {
      reg.add({ category: "Payment processors", name: "Stripe", version: "v3", icon: "stripe", url: "https://stripe.com", confidence: 100, layer: "L4_JS_GLOBALS", rule: 'script[src*="js.stripe.com/v3"]', detail: "Stripe v3 payment SDK detected" });
    }
    if (matchAsset(scriptSrcs, /(?:google\.com|gstatic\.com)\/recaptcha/i) || htmlLower.includes("g-recaptcha")) {
      reg.add({ category: "Security", name: "reCAPTCHA", version: null, icon: "recaptcha", url: "https://www.google.com/recaptcha/", confidence: 100, layer: "L3_DOM_META", rule: "google.com/recaptcha / .g-recaptcha", detail: "Google reCAPTCHA widget detected" });
    }
    if (matchAsset(scriptSrcs, /challenges\.cloudflare\.com\/turnstile/i) || htmlLower.includes("cf-turnstile")) {
      reg.add({ category: "Security", name: "Cloudflare Turnstile", version: null, icon: "cloudflare", url: "https://www.cloudflare.com/products/turnstile/", confidence: 100, layer: "L3_DOM_META", rule: "challenges.cloudflare.com/turnstile", detail: "Cloudflare Turnstile widget detected" });
    }
    if (matchAsset(scriptSrcs, /js\.hcaptcha\.com/i) || htmlLower.includes("h-captcha")) {
      reg.add({ category: "Security", name: "hCaptcha", version: null, icon: "shield", url: "https://www.hcaptcha.com", confidence: 100, layer: "L3_DOM_META", rule: "js.hcaptcha.com / .h-captcha", detail: "hCaptcha verification widget detected" });
    }
    if (matchAsset(scriptSrcs, /embed\.tawk\.to/i) || /embed\.tawk\.to/i.test(srcHtml)) {
      reg.add({ category: "Live chat", name: "Tawk.to", version: null, icon: "code", url: "https://www.tawk.to", confidence: 100, layer: "L3_DOM_META", rule: "embed.tawk.to widget", detail: "Tawk.to live chat script detected" });
    }
  }

  // Optional DNS TXT verification signals when HTTP could not provide HTML (partial DNS-only scan)
  if ((!html || html.length === 0) && dnsTxt) {
    if (dnsTxt.includes("google-site-verification")) {
      reg.add({ category: "Analytics", name: "Google Search Console", version: null, icon: "google-analytics", url: "https://search.google.com/search-console", confidence: 100, layer: "L1_NETWORK", rule: "DNS TXT google-site-verification", detail: "Verified via public DNS TXT record" });
    }
    if (dnsTxt.includes("spf.protection.outlook.com") || dnsTxt.includes("ms=")) {
      reg.add({ category: "Email", name: "Microsoft 365", version: null, icon: "microsoft", url: "https://www.microsoft.com/microsoft-365", confidence: 95, layer: "L1_NETWORK", rule: "DNS TXT SPF/Outlook verification", detail: "Microsoft 365 DNS TXT signature detected" });
    }
    if (dnsTxt.includes("_spf.google.com")) {
      reg.add({ category: "Email", name: "Google Workspace", version: null, icon: "google-analytics", url: "https://workspace.google.com", confidence: 95, layer: "L1_NETWORK", rule: "DNS TXT _spf.google.com", detail: "Google Workspace SPF record detected" });
    }
  }

  return reg.build();
}

/**
 * Distribute category groups into two visually balanced columns following Wappalyzer extension ordering.
 */
export function distributeColumns(technologies = []) {
  const leftPriority = [
    "CMS",
    "Analytics",
    "Blogs",
    "Video players",
    "Font scripts",
    "Web servers",
    "Web frameworks",
    "Programming languages",
    "Operating systems",
    "Security",
    "PaaS",
    "Hosting",
    "Hosting panels",
    "DNS",
    "Static site generator",
    "LMS",
    "Documentation",
    "Wikis"
  ];

  const rightPriority = [
    "Maps",
    "Page builders",
    "JavaScript libraries",
    "JavaScript frameworks",
    "JavaScript graphics",
    "UI frameworks",
    "Ecommerce",
    "Payment processors",
    "CDN",
    "Caching",
    "Network",
    "Tag managers",
    "SEO",
    "Issue trackers",
    "Live chat",
    "Email"
  ];

  const leftColumn = [];
  const rightColumn = [];

  for (const group of technologies) {
    if (leftPriority.includes(group.category)) {
      leftColumn.push(group);
    } else if (rightPriority.includes(group.category)) {
      rightColumn.push(group);
    } else {
      const leftWeight = leftColumn.reduce((s, g) => s + g.items.length + 1, 0);
      const rightWeight = rightColumn.reduce((s, g) => s + g.items.length + 1, 0);
      if (leftWeight <= rightWeight) leftColumn.push(group);
      else rightColumn.push(group);
    }
  }

  // Sort within each column according to canonical Wappalyzer priority order
  leftColumn.sort((a, b) => {
    const ia = leftPriority.indexOf(a.category);
    const ib = leftPriority.indexOf(b.category);
    return (ia === -1 ? 999 : ia) - (ib === -1 ? 999 : ib);
  });
  rightColumn.sort((a, b) => {
    const ia = rightPriority.indexOf(a.category);
    const ib = rightPriority.indexOf(b.category);
    return (ia === -1 ? 999 : ia) - (ib === -1 ? 999 : ib);
  });

  // Prevent completely one-sided layouts when >= 2 categories exist
  if (leftColumn.length === 0 && rightColumn.length > 1) {
    leftColumn.push(rightColumn.shift());
  } else if (rightColumn.length === 0 && leftColumn.length > 1) {
    rightColumn.push(leftColumn.pop());
  }

  return { leftColumn, rightColumn };
}

