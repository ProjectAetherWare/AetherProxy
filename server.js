// server.js
import express from "express";
import fetch from "node-fetch"; // if your Node supports global fetch, you can skip this
import cheerio from "cheerio";
import rateLimit from "express-rate-limit";
import { URL } from "url";
import dns from "dns/promises";

const app = express();
const PORT = process.env.PORT || 3000;
const ALLOW_LIST = []; // optional: list of allowed hostnames

// simple rate limiter
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60, // max requests per window per IP
});
app.use(limiter);

// helper: block requests to local/private IP ranges
function isPrivateIP(ip) {
  // basic checks for IPv4 private ranges
  if (!ip) return false;
  return (
    ip.startsWith("10.") ||
    ip.startsWith("192.168.") ||
    ip.startsWith("172.") && (() => {
      const second = parseInt(ip.split(".")[1], 10);
      return second >= 16 && second <= 31;
    })()
  );
}

async function resolveHostIsPrivate(hostname) {
  try {
    const addrs = await dns.lookup(hostname, { all: true });
    for (const a of addrs) {
      if (isPrivateIP(a.address)) return true;
    }
    return false;
  } catch (e) {
    return true; // err on safe side
  }
}

// Proxy endpoint: /proxy?u=<url>
app.get("/proxy", async (req, res) => {
  const raw = req.query.u;
  if (!raw) return res.status(400).send("missing url");

  let target;
  try {
    // allow both plain and encoded
    const decoded = decodeURIComponent(raw);
    target = new URL(decoded);
    if (!["http:", "https:"].includes(target.protocol)) {
      return res.status(400).send("only http/https allowed");
    }
  } catch (err) {
    return res.status(400).send("invalid url");
  }

  // optional: allowlist
  if (ALLOW_LIST.length && !ALLOW_LIST.includes(target.hostname)) {
    return res.status(403).send("host not allowed");
  }

  // block private/resolved local IPs
  if (await resolveHostIsPrivate(target.hostname)) {
    return res.status(403).send("private IPs blocked");
  }

  try {
    const upstreamResp = await fetch(target.toString(), {
      headers: { "User-Agent": req.get("User-Agent") || "ProxyBot/1.0" },
      redirect: "follow",
    });

    const contentType = upstreamResp.headers.get("content-type") || "";
    // Copy safe headers but strip dangerous ones
    res.set("x-proxy-by", "custom-proxy");
    if (upstreamResp.headers.get("cache-control")) {
      res.set("cache-control", upstreamResp.headers.get("cache-control"));
    }

    // handle HTML specially: rewrite links
    if (contentType.includes("text/html")) {
      const text = await upstreamResp.text();
      const $ = cheerio.load(text);

      function proxifyAttr(i, attrValue) {
        if (!attrValue) return attrValue;
        // make absolute URL
        try {
          const abs = new URL(attrValue, target).toString();
          return `/proxy?u=${encodeURIComponent(abs)}`;
        } catch {
          return attrValue;
        }
      }

      // rewrite anchors, links, scripts, imgs, forms
      $("a[href]").each((i, el) => {
        $(el).attr("href", proxifyAttr(i, $(el).attr("href")));
      });
      $("link[href]").each((i, el) => {
        $(el).attr("href", proxifyAttr(i, $(el).attr("href")));
      });
      $("img[src]").each((i, el) => {
        $(el).attr("src", proxifyAttr(i, $(el).attr("src")));
      });
      $("script[src]").each((i, el) => {
        $(el).attr("src", proxifyAttr(i, $(el).attr("src")));
      });
      $("form[action]").each((i, el) => {
        $(el).attr("action", proxifyAttr(i, $(el).attr("action")));
      });

      // remove CSP / frame-ancestors / x-frame options so our UI can display via iframe if needed
      // (we don't copy those headers to response)
      const out = $.html();
      // send rewritten HTML
      res.type("html").send(out);
      return;
    }

    // for non-HTML (images/css/js), pipe them through
    res.type(contentType);
    const buffer = await upstreamResp.arrayBuffer();
    res.send(Buffer.from(buffer));
  } catch (err) {
    console.error("proxy error", err);
    res.status(502).send("upstream error");
  }
});

// Minimal home so you can host the UI as a static file
app.use(express.static("public"));

app.listen(PORT, () => {
  console.log(`Proxy server listening on ${PORT}`);
});
