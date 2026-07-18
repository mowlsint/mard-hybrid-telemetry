#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

const CONFIG_PATH =
  process.env.MARD_NITTER_INSTANCE_CONFIG ||
  "config/influence/nitter_instances.json";
const INTERNAL_REPORT =
  process.env.MARD_NITTER_PREFLIGHT_REPORT ||
  "data/influence/ingest/nitter_preflight_latest.json";
const PUBLIC_REPORT =
  process.env.MARD_NITTER_PREFLIGHT_PUBLIC ||
  "public/influence_nitter_preflight.json";
const TEST_HANDLES = String(
  process.env.MARD_NITTER_PREFLIGHT_HANDLES || "XDevelopers,Alice_Weidel",
)
  .split(",")
  .map((value) => value.trim().replace(/^@/, ""))
  .filter(Boolean)
  .slice(0, 3);
const TIMEOUT_MS = Number(
  process.env.MARD_NITTER_PREFLIGHT_TIMEOUT_MS || 12000,
);
const MAX_BODY_BYTES = Number(
  process.env.MARD_NITTER_PREFLIGHT_MAX_BODY_BYTES || 1500000,
);
const USER_AGENT =
  process.env.MARD_INFLUENCE_X_USER_AGENT ||
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
    "(KHTML, like Gecko) Chrome/138.0 Safari/537.36 " +
    "MARD-HAT-Influence-Watch/0.5";

function sha256(value) {
  return crypto.createHash("sha256").update(String(value || "")).digest("hex");
}

function responseLooksBlocked(body) {
  const value = String(body || "").toLowerCase();
  return [
    "just a moment",
    "checking your browser",
    "cf-chl-",
    "attention required",
    "rate limited",
    "rate-limited",
    "instance has been rate limited",
    "enable javascript and cookies",
    "captcha",
  ].some((needle) => value.includes(needle));
}

function detectItems(body) {
  const rssItems = (String(body || "").match(/<item\b/gi) || []).length;
  const htmlItems = (
    String(body || "").match(
      /class=["'][^"']*\btimeline-item\b[^"']*["']/gi,
    ) || []
  ).length;
  const statusLinks = (
    String(body || "").match(/\/status\/\d+/gi) || []
  ).length;

  return {
    rss_items: rssItems,
    html_items: htmlItems,
    status_links: statusLinks,
    usable: rssItems > 0 || htmlItems > 0 || statusLinks > 0,
  };
}

async function readLimitedBody(response) {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel();
      throw new Error(`Response exceeded ${MAX_BODY_BYTES} bytes`);
    }
    chunks.push(value);
  }

  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8").decode(output);
}

async function probe(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "user-agent": USER_AGENT,
        accept:
          "application/rss+xml, application/xml, text/xml, text/html;q=0.9, */*;q=0.5",
        "accept-language": "en-US,en;q=0.8,de;q=0.6",
        "cache-control": "no-cache",
      },
    });
    const body = await readLimitedBody(response);
    const detected = detectItems(body);
    const blocked = responseLooksBlocked(body);

    return {
      status: response.ok && detected.usable && !blocked ? "usable" : "unusable",
      http_status: response.status,
      content_type: response.headers.get("content-type") || "",
      final_domain: (() => {
        try {
          return new URL(response.url || url).hostname;
        } catch {
          return "";
        }
      })(),
      blocked,
      ...detected,
      body_bytes: Buffer.byteLength(body, "utf8"),
      body_sha256: sha256(body),
    };
  } catch (error) {
    return {
      status: "error",
      http_status: error.httpStatus || null,
      blocked: Boolean(error.blocked),
      rss_items: 0,
      html_items: 0,
      status_links: 0,
      usable: false,
      body_bytes: 0,
      body_sha256: "",
      error:
        error?.name === "AbortError" ? "Request timeout" : error.message,
    };
  } finally {
    clearTimeout(timer);
  }
}

async function main() {
  const config = JSON.parse(await fs.readFile(CONFIG_PATH, "utf8"));
  const instances = (config.instances || [])
    .filter(
      (item) =>
        item.enabled !== false && /^https?:\/\//i.test(item.base_url || ""),
    )
    .sort(
      (left, right) =>
        Number(left.priority || 999) - Number(right.priority || 999),
    );

  const results = [];
  const usableInstances = [];

  for (const instance of instances) {
    const base = instance.base_url.replace(/\/+$/, "");
    const attempts = [];
    let usable = false;

    for (const handle of TEST_HANDLES) {
      if (instance.rss_enabled !== false) {
        const rss = await probe(`${base}/${encodeURIComponent(handle)}/rss`);
        attempts.push({ handle, mode: "rss", ...rss });
        if (rss.usable) {
          usable = true;
          break;
        }
      }

      const html = await probe(`${base}/${encodeURIComponent(handle)}`);
      attempts.push({ handle, mode: "html", ...html });
      if (html.usable) {
        usable = true;
        break;
      }
    }

    const instanceHash = sha256(base).slice(0, 16);
    results.push({
      instance_hash: instanceHash,
      usable,
      rss_enabled: instance.rss_enabled !== false,
      attempts,
    });
    if (usable) usableInstances.push(base);
  }

  const generatedAt = new Date().toISOString();
  const state = usableInstances.length ? "ok" : "unavailable";
  const internal = {
    schema_version: "1.0.0",
    generated_at: generatedAt,
    state,
    configured_instances: instances.length,
    usable_instances: usableInstances.length,
    test_handles: TEST_HANDLES,
    results,
  };
  const publicReport = {
    schema_version: "1.0.0",
    generated_at: generatedAt,
    title: "MARD Influence Watch — Nitter Preflight",
    state,
    configured_instances: instances.length,
    usable_instances: usableInstances.length,
    test_handle_count: TEST_HANDLES.length,
    status_counts: results.reduce((acc, item) => {
      const key = item.usable ? "usable" : "unusable";
      acc[key] = (acc[key] || 0) + 1;
      return acc;
    }, {}),
    assessment:
      usableInstances.length
        ? "At least one public Nitter instance returned a parseable public timeline from this GitHub runner."
        : "No configured public Nitter instance returned a parseable public timeline from this GitHub runner. X collection is skipped for this run.",
  };

  await fs.mkdir(path.dirname(INTERNAL_REPORT), { recursive: true });
  await fs.mkdir(path.dirname(PUBLIC_REPORT), { recursive: true });
  await fs.writeFile(INTERNAL_REPORT, JSON.stringify(internal, null, 2), "utf8");
  await fs.writeFile(PUBLIC_REPORT, JSON.stringify(publicReport, null, 2), "utf8");

  if (process.env.GITHUB_ENV) {
    const envLines = usableInstances.length
      ? [
          `MARD_NITTER_PREFLIGHT_USABLE=1`,
          `MARD_NITTER_INSTANCES=${usableInstances.join(",")}`,
        ]
      : [
          `MARD_NITTER_PREFLIGHT_USABLE=0`,
          `MARD_NITTER_SKIP_REASON=no_usable_public_instance_from_github_runner`,
        ];
    await fs.appendFile(process.env.GITHUB_ENV, `${envLines.join("\n")}\n`, "utf8");
  }

  console.log(
    `[nitter-preflight] configured=${instances.length} usable=${usableInstances.length} state=${state}`,
  );
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
