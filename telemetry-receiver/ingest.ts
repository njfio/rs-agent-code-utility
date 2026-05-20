// Reference Cloudflare Workers ingest handler for `rts` telemetry.
//
// NOT a deployable artifact. See `README.md`. The shape of this file
// is the contract; deploy variants will plug in real ClickHouse
// credentials and observability.

interface Env {
  // Configured via `wrangler secret put TELEMETRY_SALT`. Rotated
  // monthly by the salt-rotation cron job (see salt-rotation.md).
  TELEMETRY_SALT: string;
  // ClickHouse Cloud HTTP endpoint, e.g.
  // "https://<host>:8443/?query=INSERT+INTO+telemetry.pings+FORMAT+JSONEachRow".
  CLICKHOUSE_URL: string;
  CLICKHOUSE_AUTH: string; // "Basic <base64>"
}

const SCHEMA_VERSION = 1;

// The receiver-side allowlists MUST mirror the Rust client's bounded
// enums. Any drift here = silently accepting unknown values from the
// wire, which is a privacy-policy violation.
const ALLOWED_OS = new Set(["linux", "macos", "windows"]);
const ALLOWED_ARCH = new Set(["aarch64", "x86_64"]);
const ALLOWED_LANGS = new Set([
  "rust", "python", "typescript", "javascript", "go",
  "java", "c", "cpp", "php", "ruby", "swift", "csharp",
]);
const ALLOWED_METHODS = new Set([
  "Daemon.Ping", "Daemon.Stats", "Daemon.Cancel", "Daemon.Shutdown",
  "Workspace.Mount", "Workspace.Status", "Workspace.Unmount",
  "Session.Open", "Session.Close",
  "Index.FindSymbol", "Index.FindCallers", "Index.ImpactOf",
  "Index.ReadRange", "Index.ReadSymbol", "Index.ReadSymbolAt",
  "Index.Outline", "Index.Grep",
  "Index.Grep.multiline", "Index.Grep.structural", "Index.Grep.within_symbol",
]);
const ALLOWED_ERRORS = new Set([
  "INVALID_PARAMS", "INVALID_REQUEST", "METHOD_NOT_FOUND", "INTERNAL_ERROR",
  "OUT_OF_ROOT", "RANGE_OUT_OF_BOUNDS", "WORKSPACE_NOT_FOUND",
  "WORKSPACE_VANISHED", "WORKSPACE_MISMATCH", "INDEX_NOT_READY",
  "DEADLINE_EXCEEDED", "CANCELLED", "INVALID_STRUCTURAL_QUERY",
  "REGEX_TOO_COMPLEX", "WITHIN_SYMBOL_NOT_FOUND",
  "WITHIN_SYMBOL_TOO_MANY_DEFS", "TIMEOUT",
]);
const ALLOWED_WORKSPACE_BUCKETS = new Set([
  "lt_1k", "1k_to_10k", "10k_to_100k", "gt_100k",
]);

const UUID_V4_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SEMVER_RE = /^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$/;

function filterMap(
  raw: Record<string, unknown>,
  allowed: Set<string>,
): Record<string, number> {
  const out: Record<string, number> = {};
  for (const [k, v] of Object.entries(raw)) {
    if (!allowed.has(k)) continue;
    if (typeof v !== "number" || v < 0 || !Number.isFinite(v)) continue;
    out[k] = Math.floor(v);
  }
  return out;
}

async function hashInstallId(id: string, salt: string): Promise<string> {
  const enc = new TextEncoder();
  const data = enc.encode(`${salt}::${id}`);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

interface ValidatedPayload {
  schema_version: 1;
  install_id_hash: string;
  rts_version: string;
  os: string;
  arch: string;
  uptime_hours: number;
  languages_indexed: string[];
  method_counts: Record<string, number>;
  method_latency_p50_ms: Record<string, number>;
  method_latency_p99_ms: Record<string, number>;
  error_counts: Record<string, number>;
  cache_hit_rate: number;
  cold_walk_ms_p50: number;
  workspace_size_bucket: string;
  ingested_at: string;
}

async function validateAndShape(
  body: unknown,
  salt: string,
): Promise<ValidatedPayload | { error: string }> {
  if (typeof body !== "object" || body === null) return { error: "not-an-object" };
  const b = body as Record<string, unknown>;
  if (b.schema_version !== SCHEMA_VERSION) return { error: "schema-version-mismatch" };
  if (typeof b.install_id !== "string" || !UUID_V4_RE.test(b.install_id)) {
    return { error: "install-id-shape" };
  }
  if (typeof b.rts_version !== "string" || !SEMVER_RE.test(b.rts_version)) {
    return { error: "rts-version-shape" };
  }
  if (typeof b.os !== "string" || !ALLOWED_OS.has(b.os)) return { error: "os" };
  if (typeof b.arch !== "string" || !ALLOWED_ARCH.has(b.arch)) return { error: "arch" };
  if (typeof b.uptime_hours !== "number" || b.uptime_hours < 0) {
    return { error: "uptime-hours" };
  }
  const langs = Array.isArray(b.languages_indexed) ? b.languages_indexed : [];
  const filteredLangs = langs.filter((l): l is string => typeof l === "string" && ALLOWED_LANGS.has(l));
  if (typeof b.cache_hit_rate !== "number" || b.cache_hit_rate < 0 || b.cache_hit_rate > 1) {
    return { error: "cache-hit-rate" };
  }
  if (typeof b.cold_walk_ms_p50 !== "number" || b.cold_walk_ms_p50 < 0) {
    return { error: "cold-walk" };
  }
  if (typeof b.workspace_size_bucket !== "string" || !ALLOWED_WORKSPACE_BUCKETS.has(b.workspace_size_bucket)) {
    return { error: "workspace-bucket" };
  }
  return {
    schema_version: 1,
    install_id_hash: await hashInstallId(b.install_id, salt),
    rts_version: b.rts_version,
    os: b.os,
    arch: b.arch,
    uptime_hours: Math.floor(b.uptime_hours),
    languages_indexed: filteredLangs,
    method_counts: filterMap(
      (b.method_counts ?? {}) as Record<string, unknown>,
      ALLOWED_METHODS,
    ),
    method_latency_p50_ms: filterMap(
      (b.method_latency_p50_ms ?? {}) as Record<string, unknown>,
      ALLOWED_METHODS,
    ),
    method_latency_p99_ms: filterMap(
      (b.method_latency_p99_ms ?? {}) as Record<string, unknown>,
      ALLOWED_METHODS,
    ),
    error_counts: filterMap(
      (b.error_counts ?? {}) as Record<string, unknown>,
      ALLOWED_ERRORS,
    ),
    cache_hit_rate: b.cache_hit_rate,
    cold_walk_ms_p50: Math.floor(b.cold_walk_ms_p50),
    workspace_size_bucket: b.workspace_size_bucket,
    ingested_at: new Date().toISOString(),
  };
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    if (req.method !== "POST") return new Response("POST only", { status: 405 });
    const url = new URL(req.url);
    if (url.pathname !== "/v1/ingest") return new Response("not found", { status: 404 });
    const ctype = req.headers.get("Content-Type") || "";
    if (!ctype.startsWith("application/json")) {
      return new Response("expected application/json", { status: 415 });
    }
    // Cap payload size at 32 KiB. Legitimate payloads are ~4 KiB.
    const contentLen = parseInt(req.headers.get("Content-Length") || "0", 10);
    if (contentLen > 32 * 1024) return new Response("payload too large", { status: 413 });

    let body: unknown;
    try {
      body = await req.json();
    } catch {
      return new Response("invalid json", { status: 400 });
    }
    const shaped = await validateAndShape(body, env.TELEMETRY_SALT);
    if ("error" in shaped) {
      // Don't echo the bad payload back. The receiver-side log
      // would capture the error class, never the body.
      return new Response(`reject: ${shaped.error}`, { status: 400 });
    }
    // Insert to ClickHouse Cloud as JSONEachRow.
    const insert = await fetch(env.CLICKHOUSE_URL, {
      method: "POST",
      headers: {
        "Authorization": env.CLICKHOUSE_AUTH,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(shaped),
    });
    if (!insert.ok) {
      // Don't surface ClickHouse errors to the client (could leak
      // schema details). Return a generic 503.
      return new Response("temporarily-unavailable", { status: 503 });
    }
    return new Response("ok", { status: 204 });
  },
};
