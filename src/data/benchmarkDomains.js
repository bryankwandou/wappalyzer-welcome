export const BENCHMARK_DOMAINS = [
  // 1. Indonesian Government & Public Sector (35 domains)
  "polri.go.id", "ojk.go.id", "indonesia.go.id", "kemenkeu.go.id", "kominfo.go.id",
  "kemkes.go.id", "kemendikbud.go.id", "bkn.go.id", "pajak.go.id", "beacukai.go.id",
  "jakarta.go.id", "jabarprov.go.id", "jatengprov.go.id", "jatimprov.go.id", "baliprov.go.id",
  "kemenlu.go.id", "kemenag.go.id", "bpk.go.id", "mahkamahagung.go.id", "kpu.go.id",
  "bawaslu.go.id", "bps.go.id", "bmkg.go.id", "batan.go.id", "bppt.go.id",
  "dephub.go.id", "esdm.go.id", "kemendag.go.id", "kemenperin.go.id", "pertanian.go.id",
  "menpan.go.id", "setneg.go.id", "setkab.go.id", "kemhan.go.id", "kkp.go.id",

  // 2. Universities & Higher Education (35 domains)
  "fti.uajy.ac.id", "uajy.ac.id", "ui.ac.id", "ugm.ac.id", "itb.ac.id",
  "its.ac.id", "unair.ac.id", "undip.ac.id", "unpad.ac.id", "ub.ac.id",
  "ipb.ac.id", "uns.ac.id", "binus.ac.id", "telkomuniversity.ac.id", "atmajaya.ac.id",
  "trisakti.ac.id", "tarumanagara.ac.id", "unpar.ac.id", "ukwms.ac.id", "petra.ac.id",
  "unesa.ac.id", "unram.ac.id", "unhas.ac.id", "unsrat.ac.id", "usu.ac.id",
  "unsri.ac.id", "unila.ac.id", "unand.ac.id", "unp.ac.id", "uny.ac.id",
  "upi.edu", "mit.edu", "stanford.edu", "harvard.edu", "ox.ac.uk",

  // 3. Global Tech, Cloud & Infrastructure (45 domains)
  "github.com", "gitlab.com", "vercel.com", "netlify.com", "cloudflare.com",
  "aws.amazon.com", "google.com", "apple.com", "microsoft.com", "meta.com",
  "stripe.com", "twilio.com", "datadog.com", "docker.com", "mongodb.com",
  "postgresql.org", "redis.io", "supabase.com", "hashicorp.com", "sentry.io",
  "npm.js", "deno.com", "bun.sh", "vite.dev", "nextjs.org",
  "nuxt.com", "svelte.dev", "vuejs.org", "react.dev", "angular.dev",
  "tailwindcss.com", "getbootstrap.com", "kubernetes.io", "elastic.co", "grafana.com",
  "kafka.apache.org", "nginx.org", "apache.org", "fastly.com", "digitalocean.com",
  "linode.com", "heroku.com", "render.com", "railway.app", "fly.io",

  // 4. E-Commerce & Retail (35 domains)
  "shopify.com", "amazon.com", "tokopedia.com", "shopee.co.id", "bukalapak.com",
  "blibli.com", "ebay.com", "walmart.com", "aliexpress.com", "target.com",
  "etsy.com", "zalora.co.id", "lazada.co.id", "ikea.com", "nike.com",
  "adidas.com", "zara.com", "hm.com", "uniqlo.com", "sephora.com",
  "bestbuy.com", "costco.com", "wayfair.com", "overstock.com", "homedepot.com",
  "lowes.com", "aliexpress.us", "rakuten.co.jp", "mercadolibre.com", "jd.id",
  "matahari.com", "erfonline.com", "sociolla.com", "orami.co.id", "ruparupa.com",

  // 5. News, Media & Publishing (40 domains)
  "detik.com", "kompas.com", "cnnindonesia.com", "tempo.co", "tribunnews.com",
  "liputan6.com", "merdeka.com", "kumparan.com", "nytimes.com", "bbc.com",
  "theguardian.com", "reuters.com", "bloomberg.com", "techcrunch.com", "theverge.com",
  "wired.com", "arstechnica.com", "forbes.com", "wsj.com", "washingtonpost.com",
  "vice.com", "vox.com", "buzzfeed.com", "huffpost.com", "economist.com",
  "ft.com", "cnbc.com", "businessinsider.com", "mashable.com", "engadget.com",
  "zdnet.com", "cnet.com", "republika.co.id", "sindonews.com", "suara.com",
  "antara.co.id", "mediaindonesia.com", "bisnis.com", "katadata.co.id", "tirto.id",

  // 6. Modern Web3, Crypto & Gaming (35 domains)
  "blockbite.fun", "binance.com", "coinbase.com", "uniswap.org", "opensea.io",
  "etherscan.io", "coingecko.com", "coinmarketcap.com", "solana.com", "polygon.technology",
  "chainlink.com", "arbitrum.io", "avalanche.org", "cosmos.network", "sui.io",
  "near.org", "phantom.app", "metamask.io", "aave.com", "makerdao.com",
  "curve.fi", "compound.finance", "dydx.exchange", "synthetix.io", "sushi.com",
  "pancakeswap.finance", "1inch.io", "immutable.com", "sandbox.game", "axieinfinity.com",
  "decentraland.org", "blur.io", "magicden.io", "kraken.com", "kucoin.com",

  // 7. Banking, FinTech & Enterprise Services (25 domains)
  "bca.co.id", "mandiri.co.id", "bni.co.id", "bri.co.id", "cimbniaga.co.id",
  "jago.com", "jenius.com", "plaid.com", "revolut.com", "wise.com",
  "robinhood.com", "chime.com", "monzo.com", "klarna.com", "square.com",
  "paypal.com", "adyen.com", "affirm.com", "sofi.com", "brex.com",
  "ramp.com", "bill.com", "expensify.com", "gusto.com", "rippling.com"
];

export function getDomainSector(domain) {
  if (domain.endsWith(".go.id") || domain.endsWith(".gov")) return "Pemerintahan / Publik";
  if (domain.endsWith(".ac.id") || domain.endsWith(".edu") || domain.endsWith(".ac.uk")) return "Universitas / Riset";
  if (["blockbite.fun", "binance.com", "coinbase.com", "uniswap.org", "opensea.io", "etherscan.io", "coingecko.com", "coinmarketcap.com", "solana.com", "polygon.technology", "chainlink.com", "arbitrum.io", "avalanche.org", "cosmos.network", "sui.io", "near.org", "phantom.app", "metamask.io", "aave.com", "makerdao.com", "curve.fi", "compound.finance", "dydx.exchange", "synthetix.io", "sushi.com", "pancakeswap.finance", "1inch.io", "immutable.com", "sandbox.game", "axieinfinity.com", "decentraland.org", "blur.io", "magicden.io", "kraken.com", "kucoin.com"].includes(domain)) return "Web3 / Kripto";
  if (["bca.co.id", "mandiri.co.id", "bni.co.id", "bri.co.id", "cimbniaga.co.id", "jago.com", "jenius.com", "plaid.com", "revolut.com", "wise.com", "robinhood.com", "chime.com", "monzo.com", "klarna.com", "square.com", "paypal.com", "adyen.com", "affirm.com", "sofi.com", "brex.com", "ramp.com", "bill.com", "expensify.com", "gusto.com", "rippling.com"].includes(domain)) return "Perbankan / FinTech";
  if (["shopify.com", "amazon.com", "tokopedia.com", "shopee.co.id", "bukalapak.com", "blibli.com", "ebay.com", "walmart.com", "aliexpress.com", "target.com", "etsy.com", "zalora.co.id", "lazada.co.id", "ikea.com", "nike.com", "adidas.com", "zara.com", "hm.com", "uniqlo.com", "sephora.com", "bestbuy.com", "costco.com", "wayfair.com", "overstock.com", "homedepot.com", "lowes.com", "aliexpress.us", "rakuten.co.jp", "mercadolibre.com", "jd.id", "matahari.com", "erfonline.com", "sociolla.com", "orami.co.id", "ruparupa.com"].includes(domain)) return "E-Commerce";
  if (["detik.com", "kompas.com", "cnnindonesia.com", "tempo.co", "tribunnews.com", "liputan6.com", "merdeka.com", "kumparan.com", "nytimes.com", "bbc.com", "theguardian.com", "reuters.com", "bloomberg.com", "techcrunch.com", "theverge.com", "wired.com", "arstechnica.com", "forbes.com", "wsj.com", "washingtonpost.com", "vice.com", "vox.com", "buzzfeed.com", "huffpost.com", "economist.com", "ft.com", "cnbc.com", "businessinsider.com", "mashable.com", "engadget.com", "zdnet.com", "cnet.com", "republika.co.id", "sindonews.com", "suara.com", "antara.co.id", "mediaindonesia.com", "bisnis.com", "katadata.co.id", "tirto.id"].includes(domain)) return "Media / Berita";
  return "Cloud / SaaS";
}
