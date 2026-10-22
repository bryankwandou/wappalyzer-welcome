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
    const timeout = setTimeout(() => controller.abort(), 2800);

    const targetUrl = `https://${domain}`;
    const response = await fetch(targetUrl, {
      method: "GET",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Wappalyzer-Verifier/6.5.0",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
      },
      signal: controller.signal
    });
    clearTimeout(timeout);

    const status = response.status;
    const headers = Object.fromEntries(response.headers.entries());
    const vercelError = headers["x-vercel-error"] || "";

    let bodyText = "";
    if (status === 404) {
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

    return res.status(200).json({
      domain,
      status,
      isGhost,
      reason: isGhost ? (vercelError || "404 Target Deployment Not Found") : null,
      server: headers["server"] || null,
      reachable: !isGhost && status < 500
    });
  } catch (err) {
    return res.status(200).json({
      domain,
      status: 0,
      isGhost: true,
      reason: `Koneksi gagal atau host tidak ditemukan: ${err.message}`,
      reachable: false
    });
  }
}
