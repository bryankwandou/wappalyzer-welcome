/**
 * Real-Time Technographic Probe & Dynamic Inspection API
 * Executes SSRF-hardened live DNS + multi-hop HTTP inspection and 5-layer signature extraction.
 */

import dns from "node:dns/promises";
import {
  normalizeDomain,
  validateHostname,
  isPrivateIp,
  extractSignatures
} from "../src/engine/signatureEngine.js";

const FETCH_TIMEOUT_MS = 7000;
const TOTAL_HTTP_BUDGET_MS = 8500;
const DNS_TIMEOUT_MS = 2200;
const MAX_REDIRECTS = 4;
const MAX_BODY_BYTES = 512 * 1024;
const CACHE_TTL_MS = 60 * 1000;
const CACHE_MAX_ENTRIES = 100;

const responseCache = new Map();

function getCached(domain) {
  const entry = responseCache.get(domain);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    responseCache.delete(domain);
    return null;
  }
  return entry.data;
}

function setCached(domain, data) {
  if (responseCache.size >= CACHE_MAX_ENTRIES) {
    const oldestKey = responseCache.keys().next().value;
    if (oldestKey) responseCache.delete(oldestKey);
  }
  responseCache.set(domain, { data, expiresAt: Date.now() + CACHE_TTL_MS });
}

/**
 * Resolve DNS via native OS resolver + Cloudflare DoH for NS/CNAME/TXT enrichment.
 * Strictly checks all resolved IPs against private/loopback/metadata CIDR blocks.
 */
async function resolveAndValidateDns(domain) {
  const dnsInfo = {
    ip: null,
    ips: [],
    cname: null,
    nameservers: [],
    txt: [],
    nxdomain: false,
    ssrfBlocked: false,
    blockReason: null
  };

  // 1. Authoritative lookup via Node DNS
  let lookupResults = [];
  try {
    lookupResults = await dns.lookup(domain, { all: true });
  } catch (err) {
    if (err && (err.code === "ENOTFOUND" || err.code === "ENODATA")) {
      // Check www.<domain> before declaring NXDOMAIN
      try {
        lookupResults = await dns.lookup(`www.${domain}`, { all: true });
      } catch {
        dnsInfo.nxdomain = true;
      }
    }
  }

  for (const rec of lookupResults) {
    if (rec && rec.address) {
      if (isPrivateIp(rec.address)) {
        dnsInfo.ssrfBlocked = true;
        dnsInfo.blockReason = `Akses diblokir: host ${domain} mengarah ke alamat IP privat/internal (${rec.address}).`;
        return dnsInfo;
      }
      dnsInfo.ips.push(rec.address);
    }
  }
  if (dnsInfo.ips.length > 0) {
    dnsInfo.ip = dnsInfo.ips[0];
    dnsInfo.nxdomain = false;
  }

  // 2. Enrich with Cloudflare DoH (A, NS, TXT) without blocking slow networks
  const dohController = new AbortController();
  const dohTimer = setTimeout(() => dohController.abort(), DNS_TIMEOUT_MS);
  try {
    const [aRes, nsRes, txtRes] = await Promise.all([
      fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`, {
        headers: { Accept: "application/dns-json" },
        signal: dohController.signal
      }).then((r) => (r.ok ? r.json() : null)).catch(() => null),
      fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=NS`, {
        headers: { Accept: "application/dns-json" },
        signal: dohController.signal
      }).then((r) => (r.ok ? r.json() : null)).catch(() => null),
      fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=TXT`, {
        headers: { Accept: "application/dns-json" },
        signal: dohController.signal
      }).then((r) => (r.ok ? r.json() : null)).catch(() => null)
    ]);

    if (aRes) {
      if (aRes.Status === 3 && dnsInfo.ips.length === 0) {
        dnsInfo.nxdomain = true;
      }
      if (Array.isArray(aRes.Answer)) {
        for (const ans of aRes.Answer) {
          if (ans.type === 1 && ans.data) {
            if (isPrivateIp(ans.data)) {
              dnsInfo.ssrfBlocked = true;
              dnsInfo.blockReason = `Akses diblokir: DNS A-record mengarah ke IP privat (${ans.data}).`;
              return dnsInfo;
            }
            if (!dnsInfo.ip) dnsInfo.ip = ans.data;
            if (!dnsInfo.ips.includes(ans.data)) dnsInfo.ips.push(ans.data);
            dnsInfo.nxdomain = false;
          } else if (ans.type === 5 && ans.data && !dnsInfo.cname) {
            dnsInfo.cname = String(ans.data).replace(/\.$/, "");
          }
        }
      }
    }

    if (nsRes && Array.isArray(nsRes.Answer)) {
      dnsInfo.nameservers = nsRes.Answer
        .filter((ans) => ans.type === 2 && ans.data)
        .map((ans) => String(ans.data).replace(/\.$/, ""));
    }

    if (txtRes && Array.isArray(txtRes.Answer)) {
      dnsInfo.txt = txtRes.Answer
        .filter((ans) => ans.type === 16 && ans.data)
        .map((ans) => String(ans.data).replace(/^"|"$/g, ""));
    }
  } catch {
    // DoH enrichment is optional; native lookup already succeeded
  } finally {
    clearTimeout(dohTimer);
  }

  return dnsInfo;
}

/**
 * Read bounded UTF-8 response text up to MAX_BODY_BYTES to prevent memory exhaustion.
 */
async function readBoundedText(response) {
  if (!response.body || typeof response.body.getReader !== "function") {
    const full = await response.text().catch(() => "");
    return full.slice(0, MAX_BODY_BYTES);
  }

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;

  try {
    while (total < MAX_BODY_BYTES) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        const remaining = MAX_BODY_BYTES - total;
        if (value.byteLength > remaining) {
          chunks.push(value.subarray(0, remaining));
          total += remaining;
          await reader.cancel().catch(() => {});
          break;
        }
        chunks.push(value);
        total += value.byteLength;
      }
    }
  } catch {
    // Return partial content already buffered
  } finally {
    reader.releaseLock();
  }

  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(merged);
}

/**
 * SSRF-safe manual redirect HTTP fetch: validates every redirect hop hostname and resolved IP.
 */
async function safeFetchWithRedirects(initialUrl, timeoutMs = FETCH_TIMEOUT_MS) {
  let currentUrl = initialUrl;
  const allSetCookies = [];

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const parsed = new URL(currentUrl);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      throw new Error("Unsupported protocol in redirect chain");
    }

    // Re-validate redirect targets on hops > 0
    if (hop > 0) {
      const hopHost = normalizeDomain(parsed.hostname);
      const hopValidation = validateHostname(hopHost);
      if (!hopValidation.valid) {
        throw new Error(`Redirect target blocked: ${hopValidation.reason}`);
      }
      const hopIps = await dns.lookup(parsed.hostname, { all: true }).catch(() => []);
      for (const rec of hopIps) {
        if (isPrivateIp(rec.address)) {
          throw new Error(`Redirect SSRF blocked (${rec.address})`);
        }
      }
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Math.max(1500, timeoutMs));

    let response;
    try {
      response = await fetch(currentUrl, {
        method: "GET",
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
          Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Language": "en-US,en;q=0.9,id;q=0.8"
        },
        redirect: "manual",
        signal: controller.signal
      });
    } finally {
      clearTimeout(timer);
    }

    if (typeof response.headers.getSetCookie === "function") {
      allSetCookies.push(...response.headers.getSetCookie());
    } else {
      const sc = response.headers.get("set-cookie");
      if (sc) allSetCookies.push(sc);
    }

    const isRedirect = response.status >= 300 && response.status < 400;
    const location = response.headers.get("location");
    if (isRedirect && location && hop < MAX_REDIRECTS) {
      // Cancel unused redirect body
      await response.body?.cancel().catch(() => {});
      currentUrl = new URL(location, currentUrl).toString();
      continue;
    }

    return { response, finalUrl: currentUrl, setCookies: allSetCookies };
  }

  throw new Error("Exceeded maximum redirect hops");
}

function isPlatformGhostResponse(domain, status, headers, bodyText) {
  if (status !== 404) return false;
  const vercelErr = headers["x-vercel-error"] || "";
  if (vercelErr === "DEPLOYMENT_NOT_FOUND") return true;
  if (bodyText.includes("DEPLOYMENT_NOT_FOUND")) return true;
  if (bodyText.includes("There isn't a GitHub Pages site here")) return true;
  if (domain.endsWith(".vercel.app") && bodyText.includes("404: NOT_FOUND")) return true;
  if (domain.endsWith(".netlify.app") && (headers["server"] || "").toLowerCase() === "netlify" && bodyText.includes("Page Not Found")) return true;
  return false;
}

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  const rawDomain = (req.query && req.query.domain) || "";
  const domain = normalizeDomain(String(rawDomain));
  const validation = validateHostname(domain);

  if (!validation.valid) {
    return res.status(400).json({
      domain: domain || String(rawDomain).trim(),
      status: 0,
      isGhost: true,
      isInvalid: true,
      errorCode: validation.code,
      reason: validation.reason,
      reachable: false,
      totalCount: 0,
      technologies: [],
      evidence: []
    });
  }

  const bypassCache = req.query && req.query.fresh === "1";
  if (!bypassCache) {
    const cached = getCached(domain);
    if (cached) {
      return res.status(200).json({ ...cached, cached: true });
    }
  }

  const startTime = Date.now();

  // Step 1: DNS Resolution & SSRF Private-IP Check
  const dnsInfo = await resolveAndValidateDns(domain);
  if (dnsInfo.ssrfBlocked) {
    return res.status(403).json({
      domain,
      status: 0,
      isGhost: true,
      isInvalid: true,
      errorCode: "SSRF_BLOCKED",
      reason: dnsInfo.blockReason,
      reachable: false,
      totalCount: 0,
      technologies: [],
      evidence: []
    });
  }

  if (dnsInfo.nxdomain && dnsInfo.ips.length === 0) {
    const ghostPayload = {
      domain,
      status: 0,
      isGhost: true,
      reason: "RFC-1035 NXDOMAIN: Domain tidak terdaftar atau tidak memiliki DNS A-record aktif di internet publik",
      reachable: false,
      responseTimeMs: Date.now() - startTime,
      dns: dnsInfo,
      totalCount: 0,
      technologies: [],
      evidence: []
    };
    setCached(domain, ghostPayload);
    return res.status(200).json(ghostPayload);
  }

  // Step 2: Budget-Aware Multi-Protocol Live HTTP Probe (https apex -> https www -> http apex)
  // Retries www. when apex returns transient 5xx or 403 while staying within serverless budget.
  const candidateUrls = [
    `https://${domain}`,
    `https://www.${domain}`,
    `http://${domain}`
  ];

  let fetchResult = null;
  let fallbackResult = null;
  let lastError = null;
  const httpStart = Date.now();

  for (const candidate of candidateUrls) {
    const remainingBudget = TOTAL_HTTP_BUDGET_MS - (Date.now() - httpStart);
    if (remainingBudget < 1200) break;
    try {
      const attempt = await safeFetchWithRedirects(candidate, Math.min(FETCH_TIMEOUT_MS, remainingBudget));
      const attemptStatus = attempt.response.status;
      if (attemptStatus >= 200 && attemptStatus < 400) {
        if (fallbackResult) {
          await fallbackResult.response.body?.cancel().catch(() => {});
        }
        fetchResult = attempt;
        break;
      }
      // Keep first 4xx/5xx response as fallback, and try www. for a clean 200 if budget allows
      if (!fallbackResult) {
        fallbackResult = attempt;
      } else {
        await attempt.response.body?.cancel().catch(() => {});
      }
      // Do not fall back from HTTPS 403/404/5xx to plaintext HTTP unless HTTPS failed entirely
      if (candidate.startsWith("https://www.")) break;
    } catch (err) {
      lastError = err;
      if (err && /SSRF|Redirect target blocked/i.test(err.message)) {
        if (fallbackResult) {
          await fallbackResult.response.body?.cancel().catch(() => {});
        }
        return res.status(403).json({
          domain,
          status: 0,
          isGhost: true,
          isInvalid: true,
          errorCode: "SSRF_BLOCKED",
          reason: err.message,
          reachable: false,
          totalCount: 0,
          technologies: [],
          evidence: []
        });
      }
    }
  }

  if (!fetchResult && fallbackResult) {
    fetchResult = fallbackResult;
  }

  const responseTime = Date.now() - startTime;

  // Step 3: If DNS is ACTIVE but HTTP timed out / dropped by firewall, return honest partial DNS/Network results
  if (!fetchResult) {
    const { technologies, evidence, totalCount } = extractSignatures({
      domain,
      finalUrl: "",
      protocol: "dns:",
      status: 0,
      headers: {},
      setCookies: [],
      html: "",
      dns: dnsInfo
    });

    const partialPayload = {
      domain,
      status: 0,
      isGhost: false,
      partialScan: true,
      scanNote: `Host aktif di DNS (${dnsInfo.ip || "resolved"}), namun permintaan HTTP gagal/timeout (${lastError ? lastError.message : "timeout"})`,
      responseTimeMs: responseTime,
      dns: dnsInfo,
      server: null,
      xPoweredBy: null,
      technologies,
      evidence,
      totalCount,
      isLiveScan: true
    };
    return res.status(200).json(partialPayload);
  }

  const { response, finalUrl, setCookies } = fetchResult;
  const status = response.status;
  const headers = Object.fromEntries(response.headers.entries());
  const contentType = (headers["content-type"] || "").toLowerCase();

  let bodyText = "";
  const readableStatus = [200, 201, 301, 302, 401, 403, 404, 405, 503].includes(status);
  const isTextLike = !contentType || contentType.includes("text/") || contentType.includes("html") || contentType.includes("xml") || contentType.includes("json");
  if (readableStatus && isTextLike) {
    bodyText = await readBoundedText(response);
  } else {
    await response.body?.cancel().catch(() => {});
  }

  // Step 4: Platform Ghost Deployment Verification
  if (isPlatformGhostResponse(domain, status, headers, bodyText)) {
    const ghostPayload = {
      domain,
      status,
      isGhost: true,
      reason: headers["x-vercel-error"] || "Target deployment tidak ditemukan di platform hosting publik (404 Not Found)",
      reachable: false,
      responseTimeMs: responseTime,
      dns: dnsInfo,
      totalCount: 0,
      technologies: [],
      evidence: []
    };
    setCached(domain, ghostPayload);
    return res.status(200).json(ghostPayload);
  }

  // Step 5: 5-Layer Live Signature & Implication Extraction
  const finalProtocol = (() => {
    try {
      return new URL(finalUrl).protocol;
    } catch {
      return "https:";
    }
  })();

  const { technologies, evidence, totalCount } = extractSignatures({
    domain,
    finalUrl,
    protocol: finalProtocol,
    status,
    headers,
    setCookies,
    html: bodyText,
    dns: dnsInfo
  });

  const isF5WafPage = /The requested URL was rejected\.\s*Please consult with your administrator/i.test(bodyText) && /support ID is:/i.test(bodyText);
  const isPartial = status === 403 || status === 503 || status === 502 || isF5WafPage;
  let scanNote = null;
  if (isF5WafPage) {
    scanNote = "WAF F5 BIG-IP ASM memblokir ekstraksi DOM penuh; menampilkan deteksi header, cookie, dan WAF aktual.";
  } else if (status === 403 || status === 503 || status === 502) {
    scanNote = `Server merespons HTTP ${status} (proteksi WAF atau gangguan upstream); deteksi didasarkan pada header, cookie, dan DNS aktual.`;
  }

  const payload = {
    domain,
    finalUrl,
    protocol: finalProtocol,
    status,
    isGhost: false,
    partialScan: isPartial,
    scanNote,
    responseTimeMs: responseTime,
    dns: dnsInfo,
    server: headers["server"] || null,
    xPoweredBy: headers["x-powered-by"] || null,
    technologies,
    evidence,
    totalCount,
    isLiveScan: true
  };

  setCached(domain, payload);
  return res.status(200).json(payload);
}
