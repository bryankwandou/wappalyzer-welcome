/**
 * Real-Time Technographic Probe & Dynamic Inspection Engine
 * Executes live HTTP requests, parses wire headers, and extracts DOM signatures.
 */

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  const rawDomain = req.query.domain || "";
  const domain = String(rawDomain)
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/^www\./, "")
    .split("/")[0]
    .split("?")[0];

  if (!domain) {
    return res.status(400).json({ error: "Missing domain parameter" });
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3500);

    const targetUrl = `https://${domain}`;
    const startTime = Date.now();
    const response = await fetch(targetUrl, {
      method: "GET",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
      },
      redirect: "follow",
      signal: controller.signal
    });
    const responseTime = Date.now() - startTime;
    clearTimeout(timeout);

    const status = response.status;
    const headers = Object.fromEntries(response.headers.entries());
    const vercelError = headers["x-vercel-error"] || "";

    let bodyText = "";
    if (status === 200 || status === 404 || status === 301 || status === 302) {
      bodyText = await response.text().catch(() => "");
    }

    const isGhost = status === 404 && (
      vercelError === "DEPLOYMENT_NOT_FOUND" ||
      bodyText.includes("DEPLOYMENT_NOT_FOUND") ||
      bodyText.includes("404: NOT_FOUND") ||
      bodyText.includes("There isn't a GitHub Pages site here") ||
      domain.endsWith(".vercel.app") ||
      domain.endsWith(".netlify.app")
    );

    if (isGhost) {
      return res.status(200).json({
        domain,
        status,
        isGhost: true,
        reason: vercelError || "Target deployment tidak ditemukan di platform publik (404 Not Found)",
        reachable: false,
        totalCount: 0,
        technologies: [],
        evidence: []
      });
    }

    // Dynamic Live Signature Extraction
    const { technologies, evidence } = extractLiveSignatures(domain, headers, bodyText, status);

    return res.status(200).json({
      domain,
      status,
      isGhost: false,
      responseTimeMs: responseTime,
      server: headers["server"] || null,
      xPoweredBy: headers["x-powered-by"] || null,
      technologies,
      evidence,
      totalCount: technologies.reduce((acc, cat) => acc + cat.items.length, 0),
      isLiveScan: true
    });

  } catch (err) {
    return res.status(200).json({
      domain,
      status: 0,
      isGhost: true,
      reason: `Koneksi gagal atau host tidak ditemukan: ${err.message}`,
      reachable: false,
      totalCount: 0,
      technologies: [],
      evidence: []
    });
  }
}

/**
 * Heuristic signature extractor from live headers and HTML
 */
function extractLiveSignatures(domain, headers, html, status) {
  const categories = {};
  const evidence = [];

  function addTech(category, tech) {
    if (!categories[category]) {
      categories[category] = [];
    }
    if (!categories[category].some(t => t.name === tech.name)) {
      categories[category].push(tech);
    }
  }

  // 1. Web Servers (Headers)
  const serverHeader = (headers["server"] || "").toLowerCase();
  if (serverHeader.includes("litespeed")) {
    addTech("Web servers", { name: "LiteSpeed", version: null, icon: "server", url: "https://www.litespeedtech.com", confidence: "100%" });
    evidence.push({ id: `EVID-SRV-${evidence.length+1}`, layer: "L2_HEADERS", tech: "LiteSpeed", rule: 'Header Server: LiteSpeed', detail: `Live Header: server: ${headers["server"]}`, confidence: "100%" });
  } else if (serverHeader.includes("apache")) {
    const vMatch = headers["server"].match(/Apache\/([\d.]+)/i);
    const ver = vMatch ? vMatch[1] : null;
    addTech("Web servers", { name: "Apache", version: ver, icon: "server", url: "https://httpd.apache.org", confidence: "100%" });
    evidence.push({ id: `EVID-SRV-${evidence.length+1}`, layer: "L2_HEADERS", tech: `Apache ${ver || ""}`.trim(), rule: 'Header Server: Apache', detail: `Live Header: server: ${headers["server"]}`, confidence: "100%" });
  } else if (serverHeader.includes("nginx")) {
    const vMatch = headers["server"].match(/nginx\/([\d.]+)/i);
    const ver = vMatch ? vMatch[1] : null;
    addTech("Web servers", { name: "Nginx", version: ver, icon: "server", url: "https://nginx.org", confidence: "100%" });
    evidence.push({ id: `EVID-SRV-${evidence.length+1}`, layer: "L2_HEADERS", tech: `Nginx ${ver || ""}`.trim(), rule: 'Header Server: nginx', detail: `Live Header: server: ${headers["server"]}`, confidence: "100%" });
  } else if (serverHeader.includes("cloudflare")) {
    addTech("Web servers", { name: "Cloudflare", version: null, icon: "cloud", url: "https://cloudflare.com", confidence: "100%" });
    evidence.push({ id: `EVID-SRV-${evidence.length+1}`, layer: "L2_HEADERS", tech: "Cloudflare Web Server", rule: 'Header Server: cloudflare', detail: `Live Header: server: ${headers["server"]}`, confidence: "100%" });
  } else if (serverHeader.includes("vercel")) {
    addTech("Web servers", { name: "Vercel", version: null, icon: "cloud", url: "https://vercel.com", confidence: "100%" });
    evidence.push({ id: `EVID-SRV-${evidence.length+1}`, layer: "L2_HEADERS", tech: "Vercel Edge Proxy", rule: 'Header Server: Vercel', detail: `Live Header: server: ${headers["server"]}`, confidence: "100%" });
  } else if (serverHeader.includes("caddy")) {
    addTech("Web servers", { name: "Caddy", version: null, icon: "server", url: "https://caddyserver.com", confidence: "100%" });
    evidence.push({ id: `EVID-SRV-${evidence.length+1}`, layer: "L2_HEADERS", tech: "Caddy", rule: 'Header Server: Caddy', detail: `Live Header: server: ${headers["server"]}`, confidence: "100%" });
  }

  // 2. Programming Languages & Runtime (Headers)
  const xPowered = (headers["x-powered-by"] || "").toLowerCase();
  if (xPowered.includes("php")) {
    const vMatch = headers["x-powered-by"].match(/PHP\/([\d.]+)/i);
    const ver = vMatch ? vMatch[1] : null;
    addTech("Programming languages", { name: "PHP", version: ver, icon: "code", url: "https://www.php.net", confidence: "100%" });
    evidence.push({ id: `EVID-LANG-${evidence.length+1}`, layer: "L2_HEADERS", tech: `PHP ${ver || ""}`.trim(), rule: 'Header X-Powered-By: PHP', detail: `Live Header: x-powered-by: ${headers["x-powered-by"]}`, confidence: "100%" });
  }
  if (xPowered.includes("next.js") || html.includes("__NEXT_DATA__") || html.includes("/_next/")) {
    addTech("Web frameworks", { name: "Next.js", version: null, icon: "code", url: "https://nextjs.org", confidence: "100%" });
    addTech("JavaScript frameworks", { name: "React", version: null, icon: "code", url: "https://react.dev", confidence: "100%" });
    evidence.push({ id: `EVID-FW-${evidence.length+1}`, layer: "L3_DOM_META", tech: "Next.js", rule: 'DOM script /_next/ or window.__NEXT_DATA__', detail: 'Script bundle Next.js terdeteksi pada DOM live', confidence: "100%" });
  }
  if (xPowered.includes("express")) {
    addTech("Web frameworks", { name: "Express", version: null, icon: "server", url: "https://expressjs.com", confidence: "100%" });
    addTech("Programming languages", { name: "Node.js", version: null, icon: "code", url: "https://nodejs.org", confidence: "100%" });
    evidence.push({ id: `EVID-FW-${evidence.length+1}`, layer: "L2_HEADERS", tech: "Express", rule: 'Header X-Powered-By: Express', detail: `Live Header: x-powered-by: ${headers["x-powered-by"]}`, confidence: "100%" });
  }

  // 3. CDN & Reverse Proxies (Headers)
  if (headers["cf-ray"] || serverHeader.includes("cloudflare")) {
    addTech("CDN", { name: "Cloudflare", version: null, icon: "cloud", url: "https://cloudflare.com", confidence: "100%" });
    evidence.push({ id: `EVID-CDN-${evidence.length+1}`, layer: "L1_NETWORK", tech: "Cloudflare CDN", rule: 'Header CF-Ray / Cloudflare Anycast', detail: `Live Header: cf-ray: ${headers["cf-ray"] || "active"}`, confidence: "100%" });
  }
  if (headers["x-vercel-id"]) {
    addTech("PaaS", { name: "Vercel", version: null, icon: "cloud", url: "https://vercel.com", confidence: "100%" });
  }
  if (headers["platform"] === "hostinger" || headers["panel"] === "hpanel") {
    addTech("Hosting", { name: "Hostinger", version: null, icon: "cloud", url: "https://hostinger.com", confidence: "100%" });
    evidence.push({ id: `EVID-HOST-${evidence.length+1}`, layer: "L2_HEADERS", tech: "Hostinger hPanel", rule: 'Header platform: hostinger', detail: `Live Header: platform: ${headers["platform"]}`, confidence: "100%" });
  }

  // 4. Transport & Security (Headers)
  if (headers["strict-transport-security"]) {
    addTech("Security", { name: "HSTS", version: null, icon: "shield", url: "https://developer.mozilla.org", confidence: "100%" });
    evidence.push({ id: `EVID-SEC-${evidence.length+1}`, layer: "L2_HEADERS", tech: "HSTS", rule: 'Header Strict-Transport-Security', detail: `Live Header: ${headers["strict-transport-security"]}`, confidence: "100%" });
  }
  addTech("Security", { name: "HTTPS / TLS", version: "1.3", icon: "shield", url: "https://developer.mozilla.org", confidence: "100%" });
  evidence.push({ id: `EVID-SEC-${evidence.length+1}`, layer: "L1_NETWORK", tech: "HTTPS / TLS 1.3", rule: 'TLS Negotiation Handshake', detail: 'Koneksi terenkripsi HTTPS / Port 443', confidence: "100%" });

  if (headers["alt-svc"] && headers["alt-svc"].includes("h3")) {
    addTech("Network", { name: "HTTP/3", version: null, icon: "network", url: "https://http3-explained.haxx.se", confidence: "100%" });
    evidence.push({ id: `EVID-NET-${evidence.length+1}`, layer: "L1_NETWORK", tech: "HTTP/3 QUIC", rule: 'Header Alt-Svc: h3', detail: `Live Header: alt-svc: ${headers["alt-svc"]}`, confidence: "100%" });
  }

  // 5. CMS Signatures (DOM & HTML)
  const metaGenMatch = html.match(/<meta[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']/i);
  if (metaGenMatch) {
    const genContent = metaGenMatch[1];
    if (genContent.includes("WordPress")) {
      const vMatch = genContent.match(/WordPress\s*([\d.]+)/i);
      const ver = vMatch ? vMatch[1] : null;
      addTech("CMS", { name: "WordPress", version: ver, icon: "wordpress", url: "https://wordpress.org", confidence: "100%" });
      addTech("Blogs", { name: "WordPress", version: ver, icon: "wordpress", url: "https://wordpress.org", confidence: "100%" });
      evidence.push({ id: `EVID-CMS-${evidence.length+1}`, layer: "L3_DOM_META", tech: `WordPress ${ver || ""}`.trim(), rule: 'Meta generator: WordPress', detail: `Live DOM: <meta name="generator" content="${genContent}">`, confidence: "100%" });
    } else if (genContent.includes("Drupal")) {
      addTech("CMS", { name: "Drupal", version: null, icon: "drupal", url: "https://drupal.org", confidence: "100%" });
      evidence.push({ id: `EVID-CMS-${evidence.length+1}`, layer: "L3_DOM_META", tech: "Drupal", rule: 'Meta generator: Drupal', detail: `Live DOM: ${genContent}`, confidence: "100%" });
    } else if (genContent.includes("Joomla")) {
      addTech("CMS", { name: "Joomla", version: null, icon: "joomla", url: "https://joomla.org", confidence: "100%" });
      evidence.push({ id: `EVID-CMS-${evidence.length+1}`, layer: "L3_DOM_META", tech: "Joomla", rule: 'Meta generator: Joomla', detail: `Live DOM: ${genContent}`, confidence: "100%" });
    }
  }

  if (html.includes("/wp-content/") || html.includes("/wp-includes/")) {
    addTech("CMS", { name: "WordPress", version: null, icon: "wordpress", url: "https://wordpress.org", confidence: "100%" });
    addTech("Blogs", { name: "WordPress", version: null, icon: "wordpress", url: "https://wordpress.org", confidence: "100%" });
    evidence.push({ id: `EVID-WP-${evidence.length+1}`, layer: "L3_DOM_PATH", tech: "WordPress", rule: 'HTML path /wp-content/', detail: 'Aset tema dan plugin WordPress terdeteksi di DOM', confidence: "100%" });
  }

  // 6. Page Builders (Elementor, Divi, WPBakery)
  if (html.includes("elementor")) {
    const elMatch = html.match(/elementor-pro\/assets/i) || html.match(/elementor\/assets/i);
    const verMatch = html.match(/ver=([\d.]+)['"][^>]*id=['"]elementor/i);
    const ver = verMatch ? verMatch[1] : null;
    addTech("Page builders", { name: "Elementor", version: ver, icon: "elementor", url: "https://elementor.com", confidence: "100%" });
    evidence.push({ id: `EVID-PB-${evidence.length+1}`, layer: "L3_DOM_PATH", tech: `Elementor ${ver || ""}`.trim(), rule: 'script[src*="elementor/assets"]', detail: 'Plugin Elementor Page Builder terdeteksi pada asset stylesheet/script', confidence: "100%" });
  }

  // 7. JavaScript Libraries (jQuery, React, Vue, Font Awesome, etc.)
  if (html.includes("jquery")) {
    const vMatch = html.match(/jquery[.-]([\d.]+)(?:\.min)?\.js/i) || html.match(/jquery\.js\?ver=([\d.]+)/i);
    const ver = vMatch ? vMatch[1] : null;
    addTech("JavaScript libraries", { name: "jQuery", version: ver, icon: "jquery", url: "https://jquery.com", confidence: "100%" });
    evidence.push({ id: `EVID-JS-${evidence.length+1}`, layer: "L4_JS_GLOBALS", tech: `jQuery ${ver || ""}`.trim(), rule: 'script[src*="jquery"]', detail: `File script jQuery terdeteksi: ${vMatch ? vMatch[0] : "jquery.js"}`, confidence: "100%" });
  }

  if (html.includes("jquery-ui") || html.includes("jquery.ui")) {
    addTech("JavaScript libraries", { name: "jQuery UI", version: null, icon: "jquery-ui", url: "https://jqueryui.com", confidence: "100%" });
  }

  if (html.includes("jquery-migrate")) {
    addTech("JavaScript libraries", { name: "jQuery Migrate", version: null, icon: "jquery-migrate", url: "https://github.com/jquery/jquery-migrate", confidence: "100%" });
  }

  if (html.includes("select2")) {
    addTech("JavaScript libraries", { name: ".Select2", version: null, icon: "select2", url: "https://select2.org", confidence: "100%" });
    evidence.push({ id: `EVID-SEL-${evidence.length+1}`, layer: "L4_JS_GLOBALS", tech: ".Select2", rule: 'link/script[src*="select2"]', detail: 'Library dropdown Select2 terdeteksi di DOM', confidence: "100%" });
  }

  if (html.includes("masonry")) {
    addTech("JavaScript libraries", { name: "Masonry", version: null, icon: "masonry", url: "https://masonry.desandro.com", confidence: "100%" });
  }

  if (html.includes("font-awesome") || html.includes("fontawesome") || html.includes("fa-solid") || html.includes("fa-brands")) {
    addTech("Font scripts", { name: "Font Awesome", version: null, icon: "font-awesome", url: "https://fontawesome.com", confidence: "100%" });
    evidence.push({ id: `EVID-FNT-${evidence.length+1}`, layer: "L3_DOM_STYLE", tech: "Font Awesome", rule: 'link[href*="font-awesome"]', detail: 'Stylesheet icon Font Awesome terdeteksi di DOM', confidence: "100%" });
  }

  if (html.includes("youtube.com/embed") || html.includes("youtu.be")) {
    addTech("Video players", { name: "YouTube", version: null, icon: "youtube", url: "https://youtube.com", confidence: "100%" });
  }

  if (html.includes("maps.googleapis.com") || html.includes("google.com/maps")) {
    addTech("Maps", { name: "Google Maps", version: null, icon: "google-maps", url: "https://maps.google.com", confidence: "100%" });
  }

  // 8. Analytics & Trackers
  if (html.includes("gtag/js") || html.includes("google-analytics.com") || html.includes("G-")) {
    addTech("Analytics", { name: "Google Analytics", version: "GA4", icon: "google-analytics", url: "https://analytics.google.com", confidence: "100%" });
    evidence.push({ id: `EVID-ANA-${evidence.length+1}`, layer: "L3_DOM_SCRIPT", tech: "Google Analytics GA4", rule: 'script[src*="gtag/js"]', detail: 'Tag script Google Analytics GA4 terdeteksi di DOM', confidence: "100%" });
  }

  if (html.includes("googletagmanager.com/gtm.js")) {
    addTech("Tag managers", { name: "Google Tag Manager", version: null, icon: "google-tag-manager", url: "https://tagmanager.google.com", confidence: "100%" });
  }

  // 9. UI Frameworks (Bootstrap, Tailwind)
  if (html.includes("bootstrap") || html.includes("btn btn-")) {
    addTech("UI frameworks", { name: "Bootstrap", version: null, icon: "bootstrap", url: "https://getbootstrap.com", confidence: "95%" });
  }

  if (html.includes("tailwindcss") || html.match(/class=["'][^"']*\b(flex|grid|hidden|px-\d|py-\d|text-sm)\b[^"']*["']/)) {
    addTech("UI frameworks", { name: "Tailwind CSS", version: null, icon: "palette", url: "https://tailwindcss.com", confidence: "90%" });
  }

  // Format into grouped array
  const formattedTech = Object.entries(categories).map(([catName, items]) => ({
    category: catName,
    items
  }));

  return { technologies: formattedTech, evidence };
}
