/**
 * VibeCodersLegal — /scan API (Cloudflare Worker)
 * Real surface-level compliance scan: same checks we run in manual audits.
 * GET ?url=example.com  →  JSON { ok, target, findings[], scannedAt }
 *
 * Deploy: CF Dashboard → Workers & Pages → Create Worker → paste → Deploy.
 * No paid plan needed (free tier: 100k req/day).
 */

const ALLOWED_ORIGINS = [
  "https://vibecoderslegal.com",
  "https://www.vibecoderslegal.com",
  "http://localhost:8765", // local preview
];

const TRACKERS = [
  { re: /googletagmanager\.com|gtag\(/i, name: "Google Tag Manager / gtag", ad: false },
  { re: /google-analytics\.com|analytics\.js|ga\(\s*['"]create/i, name: "Google Analytics", ad: false },
  { re: /connect\.facebook\.net|fbq\(/i, name: "Meta (Facebook) Pixel", ad: true },
  { re: /analytics\.tiktok\.com|ttq\.load|ttq\.track/i, name: "TikTok Pixel", ad: true },
  { re: /clarity\.ms/i, name: "Microsoft Clarity (session replay)", replay: true },
  { re: /static\.hotjar\.com|hj\(/i, name: "Hotjar (session replay)", replay: true },
  { re: /cdn\.(i\.)?posthog\.com|posthog\.init/i, name: "PostHog", ad: false },
  { re: /cdn\.mixpanel\.com|mixpanel\.init/i, name: "Mixpanel", ad: false },
  { re: /cdn\.segment\.com|analytics\.load/i, name: "Segment", ad: false },
  { re: /snap\.licdn\.com/i, name: "LinkedIn Insight Tag", ad: true },
];

const CMP_RE = /cookieyes|cookiebot|onetrust|usercentrics|termly\.io|iubenda|consentmanager|klaro|osano|cookieconsent|quantcast|didomi|cookiefirst|complianz|borlabs/i;

const TRACKING_COOKIES = /^(_ga|_gid|_gat|_fbp|_fbc|_ttp|_shopify_analytics|_shopify_marketing|_hj|ajs_|mp_|ph_)/i;

function corsHeaders(origin) {
  const allow = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  };
}

function normalizeUrl(input) {
  let u = (input || "").trim().toLowerCase();
  if (!u) return null;
  u = u.replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  // very light hostname validation
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(u)) return null;
  // block obvious internal targets
  if (/^(localhost|127\.|10\.|192\.168\.|169\.254\.|0\.)/.test(u)) return null;
  return "https://" + u;
}

async function fetchPage(url) {
  const res = await fetch(url, {
    redirect: "follow",
    headers: {
      "User-Agent": "Mozilla/5.0 (compatible; VCLScan/1.0; +https://vibecoderslegal.com/scan.html)",
      "Accept": "text/html,application/xhtml+xml",
    },
    cf: { cacheTtl: 0 },
  });
  const setCookies = [];
  // Workers expose multiple Set-Cookie via getAll where supported
  if (res.headers.getAll) {
    for (const c of res.headers.getAll("set-cookie")) setCookies.push(c);
  } else {
    const c = res.headers.get("set-cookie");
    if (c) setCookies.push(c);
  }
  const reader = res.body.getReader();
  let html = "", received = 0;
  const decoder = new TextDecoder();
  while (received < 600_000) { // cap 600KB
    const { done, value } = await reader.read();
    if (done) break;
    received += value.length;
    html += decoder.decode(value, { stream: true });
  }
  try { reader.cancel(); } catch (e) {}
  return { status: res.status, finalUrl: res.url, html, setCookies };
}

function extractPolicyLinks(html, baseUrl) {
  const links = { privacy: null, terms: null };
  const re = /href=["']([^"']*)["']/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    const href = m[1];
    const low = href.toLowerCase();
    if (!links.privacy && /privacy|datenschutz|privacidad/.test(low)) links.privacy = href;
    if (!links.terms && /terms|tos|conditions|agb/.test(low)) links.terms = href;
    if (links.privacy && links.terms) break;
  }
  const resolve = (href) => {
    if (!href) return null;
    if (href === "#" || href === "/#" || href.startsWith("javascript:")) return { url: null, dead: true };
    try { return { url: new URL(href, baseUrl).href, dead: false }; } catch { return { url: null, dead: true }; }
  };
  return { privacy: resolve(links.privacy), terms: resolve(links.terms) };
}

async function checkUrlAlive(url) {
  try {
    const res = await fetch(url, { method: "GET", redirect: "follow", headers: { "User-Agent": "VCLScan/1.0" } });
    if (res.status >= 400) return false;
    // tiny page = likely SPA shell or placeholder; treat as alive (benefit of the doubt)
    return true;
  } catch { return false; }
}

function buildFindings(page, policy, privacyAlive, termsAlive) {
  const f = [];
  const html = page.html;

  const found = TRACKERS.filter(t => t.re.test(html));
  const hasCMP = CMP_RE.test(html);
  const trackCookies = page.setCookies
    .map(c => c.split("=")[0].trim())
    .filter(n => TRACKING_COOKIES.test(n));

  const adPixels = found.filter(t => t.ad);
  const replayTools = found.filter(t => t.replay);

  if (found.length && !hasCMP) {
    f.push({
      severity: "critical",
      title: `Trackers load with no consent management detected (${found.map(t => t.name).join(", ")})`,
      law: "ePrivacy Directive Art. 5(3) · EDPB Guidelines 03/2022 · UK PECR",
      detail: "Analytics/marketing scripts are present in the page source with no consent platform detected — for EU/UK visitors they need opt-in before they fire. This is the most-enforced gap in the EU; Spain's AEPD alone issues dozens of small-business fines for it yearly.",
    });
  }
  if (adPixels.length) {
    f.push({
      severity: "high",
      title: `Advertising pixels detected (${adPixels.map(t => t.name).join(", ")})`,
      law: "ePrivacy Art. 5(3) · GDPR Art. 6 — consent is the only valid basis for ad tracking",
      detail: "Ad pixels are the strictest consent tier — CNIL, AEPD and the Belgian DPA fine specifically for pixels firing pre-consent. Verify these are consent-gated, not just accompanied by a banner.",
    });
  }
  if (replayTools.length) {
    f.push({
      severity: "high",
      title: `Session-replay tooling detected (${replayTools.map(t => t.name).join(", ")})`,
      law: "ePrivacy Art. 5(3) · GDPR Art. 5(1)(c) data minimisation",
      detail: "Session replay records real user behaviour (and often form input). Without prior consent this is among the highest-risk tracker categories, and a frequent subject of CIPA wiretap class actions in the US.",
    });
  }
  if (trackCookies.length) {
    f.push({
      severity: "critical",
      title: `Tracking cookies set on first load, before any consent (${[...new Set(trackCookies)].slice(0, 5).join(", ")})`,
      law: "ePrivacy Art. 5(3)",
      detail: "These cookies were set by the server on the very first request — no consent interaction possible. Regulators verify exactly this with a clean-browser test.",
    });
  }

  if (!policy.privacy) {
    f.push({
      severity: "critical",
      title: "No privacy policy link found on the page",
      law: "GDPR Art. 13 · CCPA notice at collection",
      detail: "If personal data is collected (signup, forms, analytics), a privacy notice must be available at the point of collection. Its absence is a per-se violation, not a technicality.",
    });
  } else if (policy.privacy.dead || privacyAlive === false) {
    f.push({
      severity: "critical",
      title: "Privacy policy is linked but doesn't exist (dead link)",
      law: "GDPR Art. 13 · UCPD Art. 7 (misleading omission)",
      detail: "The footer promises a policy that isn't there — arguably worse than no link, because it implies compliance that doesn't exist.",
    });
  }
  if (!policy.terms) {
    f.push({
      severity: "high",
      title: "No terms of service link found",
      law: "Consumer Rights Directive 2011/83/EU · Brussels I bis Art. 18",
      detail: "Without terms naming a legal entity and governing law, an EU consumer can sue in their own country's court, and the contract may be unenforceable.",
    });
  } else if (policy.terms.dead || termsAlive === false) {
    f.push({
      severity: "high",
      title: "Terms of service linked but missing (dead link)",
      law: "Consumer Rights Directive 2011/83/EU",
      detail: "A dead terms link means no enforceable contract terms — entity, governing law, and liability caps are all absent.",
    });
  }

  if (found.length && hasCMP) {
    f.push({
      severity: "medium",
      title: "Consent platform detected — verify it actually blocks scripts",
      law: "EDPB Guidelines 03/2022 — prior blocking required",
      detail: "A CMP is present alongside trackers. The most common audit finding: the banner displays correctly while scripts fire anyway. Test in a private window with devtools → Network before clicking anything.",
    });
  }

  const order = { critical: 0, high: 1, medium: 2, info: 3 };
  f.sort((a, b) => order[a.severity] - order[b.severity]);
  return f;
}

export default {
  async fetch(request) {
    const origin = request.headers.get("Origin") || "";
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders(origin) });
    }
    const { searchParams } = new URL(request.url);
    const target = normalizeUrl(searchParams.get("url"));
    if (!target) {
      return new Response(JSON.stringify({ ok: false, error: "invalid_url" }), { status: 400, headers: corsHeaders(origin) });
    }
    try {
      const page = await fetchPage(target);
      if (page.status >= 400) {
        return new Response(JSON.stringify({ ok: false, error: "unreachable", status: page.status }), { status: 200, headers: corsHeaders(origin) });
      }
      const policy = extractPolicyLinks(page.html, page.finalUrl);
      const privacyAlive = policy.privacy && policy.privacy.url ? await checkUrlAlive(policy.privacy.url) : null;
      const termsAlive = policy.terms && policy.terms.url ? await checkUrlAlive(policy.terms.url) : null;
      const findings = buildFindings(page, policy, privacyAlive, termsAlive);
      return new Response(JSON.stringify({
        ok: true,
        target: page.finalUrl,
        findings,
        clean: findings.length === 0,
        note: "Surface-level scan of the public homepage HTML. JS-rendered content, inner pages, and policy text quality require a manual audit.",
        scannedAt: new Date().toISOString(),
      }), { headers: corsHeaders(origin) });
    } catch (e) {
      return new Response(JSON.stringify({ ok: false, error: "fetch_failed" }), { status: 200, headers: corsHeaders(origin) });
    }
  },
};
