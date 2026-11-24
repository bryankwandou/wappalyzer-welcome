/**
 * Comprehensive Unit, Security (SSRF/XSS), and Live Wire Probe Test Suite
 */

import assert from "node:assert/strict";
import {
  normalizeDomain,
  validateHostname,
  isPrivateIp,
  parseHtmlSignals,
  extractSignatures,
  distributeColumns
} from "../src/engine/signatureEngine.js";
import probeHandler from "../api/probe.js";
import { analyzeTargetUrl } from "../src/data/techDatabase.js";

let passed = 0;
let failed = 0;

async function runTest(name, fn) {
  try {
    await fn();
    passed += 1;
    console.log(`[PASS] ${name}`);
  } catch (err) {
    failed += 1;
    console.error(`[FAIL] ${name}: ${err.message}`);
  }
}

async function invokeProbe(query) {
  let statusCode = 200;
  let body = null;
  const req = { method: "GET", query };
  const res = {
    setHeader: () => {},
    status: (code) => {
      statusCode = code;
      return {
        json: (payload) => {
          body = payload;
          return payload;
        },
        end: () => {}
      };
    }
  };
  await probeHandler(req, res);
  return { statusCode, body };
}

console.log("=== WAPPALYZER ENGINE UNIT, SECURITY & LIVE VERIFICATION ===\n");

// 1. Normalization & Hostname Validation
await runTest("normalizeDomain strips schemes, www, ports, paths, and credentials", () => {
  assert.equal(normalizeDomain("HTTPS://WWW.Polri.GO.ID:443/berita?id=1#top"), "polri.go.id");
  assert.equal(normalizeDomain("user:pass@github.com/org/repo"), "github.com");
  assert.equal(normalizeDomain("  ojk.go.id. "), "ojk.go.id");
});

await runTest("validateHostname blocks SSRF targets, IP literals, private TLDs, bare words, and .onion", () => {
  assert.equal(validateHostname("github.com").valid, true);
  assert.equal(validateHostname("fti.uajy.ac.id").valid, true);
  assert.equal(validateHostname("localhost").valid, false);
  assert.equal(validateHostname("sub.localhost").valid, false);
  assert.equal(validateHostname("127.0.0.1").valid, false);
  assert.equal(validateHostname("169.254.169.254").valid, false);
  assert.equal(validateHostname("[::1]").valid, false);
  assert.equal(validateHostname("intranet.local").valid, false);
  assert.equal(validateHostname("service.internal").valid, false);
  assert.equal(validateHostname("lockbit").code, "MISSING_TLD");
  assert.equal(validateHostname("hidden.onion").code, "ONION_UNSUPPORTED");
});

await runTest("isPrivateIp blocks loopback, RFC1918, CGNAT, link-local metadata, and IPv6 ULA/loopback", () => {
  assert.equal(isPrivateIp("127.0.0.1"), true);
  assert.equal(isPrivateIp("10.0.0.5"), true);
  assert.equal(isPrivateIp("172.16.0.1"), true);
  assert.equal(isPrivateIp("172.31.255.254"), true);
  assert.equal(isPrivateIp("192.168.1.1"), true);
  assert.equal(isPrivateIp("169.254.169.254"), true);
  assert.equal(isPrivateIp("100.64.0.1"), true);
  assert.equal(isPrivateIp("::1"), true);
  assert.equal(isPrivateIp("::ffff:127.0.0.1"), true);
  assert.equal(isPrivateIp("fe80::1"), true);
  assert.equal(isPrivateIp("fc00::1"), true);
  assert.equal(isPrivateIp("8.8.8.8"), false);
  assert.equal(isPrivateIp("1.1.1.1"), false);
  assert.equal(isPrivateIp("172.32.0.1"), false);
  assert.equal(isPrivateIp("2606:4700:4700::1111"), false);
});

// 2. HTML Meta Attribute Order Independence & Zero False Positives
await runTest("parseHtmlSignals handles content-before-name meta tags and multiple generators", () => {
  const html = `
    <meta content="WordPress 6.7.2" name="generator">
    <meta name='generator' content='Elementor 3.25.4'>
    <script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>
    <script src="/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.4.1"></script>
    <script src="/wp-includes/js/jquery/ui/core.min.js?ver=1.13.3"></script>
    <link rel="stylesheet" href="/wp-content/plugins/elementor/assets/css/frontend.min.css?ver=3.25.4">
  `;
  const parsed = parseHtmlSignals(html);
  assert.equal(parsed.metas.length, 2);
  const res = extractSignatures({
    domain: "example.org",
    finalUrl: "https://example.org",
    protocol: "https:",
    status: 200,
    headers: { server: "nginx/1.26.1", "strict-transport-security": "max-age=31536000" },
    html
  });

  const flat = res.technologies.flatMap((g) => g.items.map((i) => ({ cat: g.category, ...i })));
  assert.equal(flat.find((x) => x.cat === "CMS" && x.name === "WordPress")?.version, "6.7.2");
  assert.equal(flat.find((x) => x.cat === "Blogs" && x.name === "WordPress")?.version, "6.7.2");
  assert.equal(flat.find((x) => x.name === "Elementor")?.version, "3.25.4");
  assert.equal(flat.find((x) => x.name === "jQuery")?.version, "3.7.1");
  assert.equal(flat.find((x) => x.name === "jQuery Migrate")?.version, "3.4.1");
  assert.equal(flat.find((x) => x.name === "jQuery UI")?.version, "1.13.3");
  assert.equal(flat.find((x) => x.name === "PHP")?.name, "PHP");
  assert.equal(flat.find((x) => x.name === "Nginx")?.version, "1.26.1");
  assert.equal(res.evidence.length, res.totalCount);
});

await runTest("extractSignatures has ZERO false positives on G- text and generic flex/grid classes", () => {
  const html = `
    <!DOCTYPE html>
    <html><body>
      <div class="flex grid hidden">IMG-1234 TAG-99 G-20 Summit SVG-icon</div>
      <p>Plain static HTML page without analytics or Tailwind.</p>
    </body></html>
  `;
  const res = extractSignatures({
    domain: "plain.example.com",
    finalUrl: "http://plain.example.com",
    protocol: "http:",
    status: 200,
    headers: { server: "Apache/2.4.58" },
    html
  });
  const names = res.technologies.flatMap((g) => g.items.map((i) => i.name));
  assert.ok(!names.includes("Google Analytics"), "Should not false-positive Google Analytics on G-20 / IMG-");
  assert.ok(!names.includes("Tailwind CSS"), "Should not false-positive Tailwind on generic flex/grid/hidden");
  assert.ok(!names.includes("HTTPS / TLS"), "Should not falsely report HTTPS on plaintext http:// response");
  assert.ok(names.includes("Apache"), "Should detect Apache from Server header");
});

await runTest("extractSignatures detects F5 BIG-IP ASM block pages and Set-Cookie markers", () => {
  const html = "<html><head><title>Request Rejected</title></head><body>The requested URL was rejected. Please consult with your administrator.<br>Your support ID is: 123456789</body></html>";
  const res = extractSignatures({
    domain: "protected.example.go.id",
    finalUrl: "https://protected.example.go.id",
    protocol: "https:",
    status: 200,
    headers: { server: "Microsoft-IIS/10.0", "x-aspnet-version": "4.0.30319" },
    setCookies: ["TS01ab34cd=012345; Path=/; HttpOnly", "ASP.NET_SessionId=xyz; Path=/"],
    html
  });
  const names = res.technologies.flatMap((g) => g.items.map((i) => i.name));
  assert.ok(names.includes("F5 BIG-IP"));
  assert.ok(names.includes("Microsoft IIS"));
  assert.ok(names.includes("ASP.NET"));
  assert.ok(names.includes("Windows Server"), "IIS should imply Windows Server");
});

await runTest("extractSignatures upgrades version when later signature is more specific", () => {
  const html = `
    <link rel="stylesheet" href="/wp-content/themes/theme/style.css" />
    <meta name="generator" content="WordPress 6.8.1" />
  `;
  const res = extractSignatures({
    domain: "wp.example.com",
    protocol: "https:",
    status: 200,
    headers: {},
    html
  });
  const cmsWp = res.technologies.find((c) => c.category === "CMS")?.items.find((i) => i.name === "WordPress");
  const blogWp = res.technologies.find((c) => c.category === "Blogs")?.items.find((i) => i.name === "WordPress");
  assert.equal(cmsWp?.version, "6.8.1");
  assert.equal(blogWp?.version, "6.8.1");
});

await runTest("distributeColumns balances categories cleanly across left and right columns", () => {
  const { leftColumn, rightColumn } = distributeColumns([
    { category: "CMS", items: [{ name: "WordPress" }] },
    { category: "Maps", items: [{ name: "Google Maps" }] },
    { category: "JavaScript libraries", items: [{ name: "jQuery" }] }
  ]);
  assert.equal(leftColumn.length, 1);
  assert.equal(rightColumn.length, 2);
});

// 3. Probe API Security Tests (SSRF & Input Validation)
await runTest("api/probe rejects SSRF IP literals, localhost, and invalid inputs with HTTP 400", async () => {
  for (const target of ["127.0.0.1", "169.254.169.254", "localhost", "LOCKBIT", "site.onion"]) {
    const { statusCode, body } = await invokeProbe({ domain: target });
    assert.equal(statusCode, 400, `Expected 400 for ${target}, got ${statusCode}`);
    assert.equal(body.isInvalid, true);
    assert.equal(body.totalCount, 0);
  }
});

// 4. Live Network Probe Integration Tests
await runTest("api/probe confirms NXDOMAIN ghost host returns isGhost=true and 0 technologies", async () => {
  const { statusCode, body } = await invokeProbe({ domain: "definitely-nonexistent-host-99887766.com" });
  assert.equal(statusCode, 200);
  assert.equal(body.isGhost, true);
  assert.equal(body.totalCount, 0);
});

await runTest("api/probe performs real live scan of github.com with non-empty verified evidence", async () => {
  const { statusCode, body } = await invokeProbe({ domain: "github.com", fresh: "1" });
  assert.equal(statusCode, 200);
  assert.equal(body.isGhost, false);
  assert.ok(body.totalCount > 0, "Expected > 0 technologies on github.com");
  assert.ok(body.evidence.length >= body.totalCount, "Every technology must have evidence");
  console.log(`       github.com -> HTTP ${body.status}, ${body.totalCount} tech(s), ${body.responseTimeMs}ms`);
});

await runTest("analyzeTargetUrl performs real live scan of vercel.com", async () => {
  const data = await analyzeTargetUrl("vercel.com", { fresh: true });
  assert.equal(data.isGhost, false);
  assert.equal(data.isLiveScan, true);
  assert.ok(data.totalCount > 0);
  const names = [...data.leftColumn, ...data.rightColumn].flatMap((g) => g.items.map((i) => i.name));
  assert.ok(names.includes("Vercel") || names.includes("Next.js") || names.includes("HTTPS / TLS"));
  console.log(`       vercel.com -> HTTP ${data.httpStatus}, ${data.totalCount} tech(s): ${names.join(", ")}`);
});

console.log(`\n=== SUMMARY: ${passed} passed, ${failed} failed ===`);
if (failed > 0) process.exit(1);

