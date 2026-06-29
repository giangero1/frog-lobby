// frogWarsSession.js
// itch.io ownership verification + Frog Wars session token system.
//
// This module is imported by server.js. It is intentionally self-contained so it
// can later be lifted into a Cloudflare Worker (Phase 2) with minimal changes.
//
// Token format: compact RS256 JWT-style string `base64url(header).base64url(payload).base64url(sig)`.
// RSA-2048 / SHA-256 is used (not Ed25519) because the Unity Mono client verifies
// tokens with System.Security.Cryptography.RSA, which is reliably supported there.
//
// Security model:
// - The backend holds ONLY the PRIVATE key (FROGWARS_SESSION_PRIVATE_KEY) and signs tokens.
// - The Unity client/host ships ONLY the PUBLIC key and verifies offline (signature + expiry).
// - The client can never mint or forge a token; a cracked client cannot connect to a real host.
// - itch ownership is checked server-side; the client never decides ownership.

import crypto from "crypto";

// ---------------------------------------------------------------------------
// Config (env)
// ---------------------------------------------------------------------------

const ITCH_GAME_ID = (process.env.ITCH_GAME_ID ?? "").trim();
const ITCH_OAUTH_CLIENT_ID = (process.env.ITCH_OAUTH_CLIENT_ID ?? "").trim();
const ITCH_API_BASE = (process.env.ITCH_API_BASE ?? "https://api.itch.io").trim().replace(/\/+$/, "");
const ITCH_DEV_BYPASS_TOKEN = (process.env.ITCH_DEV_BYPASS_TOKEN ?? "").trim();
const ITCH_API_TIMEOUT_MS = Math.max(2000, Number.parseInt(process.env.ITCH_API_TIMEOUT_MS ?? "8000", 10) || 8000);

// Master switch. Enforcement only happens when this is on AND the keys/game id are present.
// Default true, but enforcement is gated on isConfigured() so deploying server.js BEFORE
// the env vars are set does NOT brick the existing lobby.
const ITCH_OWNERSHIP_ENABLED = (process.env.ITCH_OWNERSHIP_ENABLED ?? "true").toLowerCase() !== "false";

const SESSION_TTL_HOURS = clampNumber(Number.parseInt(process.env.FROGWARS_SESSION_TTL_HOURS ?? "16", 10), 1, 24, 16);
const SESSION_TTL_SECONDS = SESSION_TTL_HOURS * 3600;
const REMEMBER_LOGIN_DAYS = clampNumber(Number.parseInt(process.env.FROGWARS_REMEMBER_LOGIN_DAYS ?? "14", 10), 1, 30, 14);
const REMEMBER_LOGIN_SECONDS = REMEMBER_LOGIN_DAYS * 24 * 3600;
// How long after issue a token may still be auto-refreshed without a fresh itch re-verify.
const SESSION_REFRESH_CUTOFF_SECONDS = clampNumber(
  Number.parseInt(process.env.FROGWARS_SESSION_REFRESH_CUTOFF_HOURS ?? "72", 10) * 3600,
  SESSION_TTL_SECONDS,
  30 * 24 * 3600,
  72 * 3600
);

const TOKEN_VERSION = 1;

// ---------------------------------------------------------------------------
// Key material
// ---------------------------------------------------------------------------
// FROGWARS_SESSION_PRIVATE_KEY accepts either a PEM string (with BEGIN/END lines)
// or a base64-encoded PEM (handy for single-line Render env values). The public
// key is derived from the private key at startup, so only ONE secret is needed.

let privateKeyObj = null;
let publicKeyPem = null;
let keyLoadError = null;

function loadPrivateKey() {
  const raw = (process.env.FROGWARS_SESSION_PRIVATE_KEY ?? "").trim();
  if (!raw) return null;

  let pem = raw;
  if (!pem.includes("BEGIN")) {
    // Treat as base64-encoded PEM.
    try {
      pem = Buffer.from(raw, "base64").toString("utf8");
    } catch {
      pem = raw;
    }
  }

  try {
    const key = crypto.createPrivateKey(pem);
    privateKeyObj = key;
    publicKeyPem = crypto.createPublicKey(key).export({ type: "spki", format: "pem" }).toString();
    keyLoadError = null;
    return key;
  } catch (error) {
    keyLoadError = error.message;
    privateKeyObj = null;
    publicKeyPem = null;
    return null;
  }
}

loadPrivateKey();

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function clampNumber(value, min, max, fallback) {
  if (!Number.isFinite(value)) return fallback;
  return Math.min(max, Math.max(min, value));
}

function base64UrlEncode(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), "utf8");
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecodeToString(input) {
  const padded = String(input).replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(padded, "base64").toString("utf8");
}

function base64UrlToBuffer(input) {
  const padded = String(input).replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(padded, "base64");
}

function maskId(value) {
  const text = String(value ?? "");
  if (text.length <= 4) return text ? "****" : "";
  return `${text.slice(0, 2)}***${text.slice(-2)}`;
}

// ---------------------------------------------------------------------------
// Configuration state
// ---------------------------------------------------------------------------

export function isConfigured() {
  return ITCH_GAME_ID.length > 0 && ITCH_OAUTH_CLIENT_ID.length > 0 && privateKeyObj != null;
}

// Whether unverified clients should actually be rejected on gated endpoints.
// Off automatically when not configured, so a server.js deploy without env vars
// keeps the existing lobby working until the operator finishes setup.
export function isEnforced() {
  return ITCH_OWNERSHIP_ENABLED && isConfigured();
}

export function missingConfigList() {
  const missing = [];
  if (ITCH_GAME_ID.length === 0) missing.push("ITCH_GAME_ID");
  if (ITCH_OAUTH_CLIENT_ID.length === 0) missing.push("ITCH_OAUTH_CLIENT_ID");
  if (privateKeyObj == null) missing.push("FROGWARS_SESSION_PRIVATE_KEY");
  return missing;
}

export function configSummaryForLog() {
  if (!ITCH_OWNERSHIP_ENABLED) return "itch ownership: DISABLED (ITCH_OWNERSHIP_ENABLED=false)";
  if (isConfigured()) return `itch ownership: ENFORCED (game ${maskId(ITCH_GAME_ID)}, ttl ${SESSION_TTL_HOURS}h, remember ${REMEMBER_LOGIN_DAYS}d)`;
  const reason = keyLoadError ? `key error: ${keyLoadError}` : `missing: ${missingConfigList().join(", ")}`;
  return `itch ownership: NOT ENFORCED (not configured — ${reason})`;
}

export function getPublicKeyPem() {
  return publicKeyPem;
}

// Surfaced in /config so the Unity client knows the gate is active.
export function configPayloadFields() {
  return {
    itchOwnershipEnforced: isEnforced(),
    itchOwnershipConfigured: isConfigured(),
    itchOauthClientId: isConfigured() ? ITCH_OAUTH_CLIENT_ID : null,
    frogSessionTtlHours: SESSION_TTL_HOURS,
    frogRememberLoginDays: REMEMBER_LOGIN_DAYS
  };
}

// ---------------------------------------------------------------------------
// Token mint / verify (RS256)
// ---------------------------------------------------------------------------

export function mintSessionToken({ itchUserId, playFabId, ownershipVerified = true, dev = false }) {
  if (!privateKeyObj) throw new Error("Signing key not configured");

  const nowSeconds = Math.floor(Date.now() / 1000);
  const itchUserIdString = String(itchUserId ?? "");
  const frogUserId = crypto.createHash("sha256").update(`frogwars:${itchUserIdString}`).digest("hex").slice(0, 24);

  const header = { alg: "RS256", typ: "JWT" };
  const payload = {
    v: TOKEN_VERSION,
    sub: frogUserId,
    itch: itchUserIdString,
    pf: playFabId ? String(playFabId) : null,
    own: Boolean(ownershipVerified),
    dev: Boolean(dev),
    iat: nowSeconds,
    exp: nowSeconds + SESSION_TTL_SECONDS
  };

  const signingInput = `${base64UrlEncode(JSON.stringify(header))}.${base64UrlEncode(JSON.stringify(payload))}`;
  const signature = crypto.sign("RSA-SHA256", Buffer.from(signingInput, "utf8"), privateKeyObj);
  const token = `${signingInput}.${base64UrlEncode(signature)}`;

  return { token, payload, expiresAtUnixMs: payload.exp * 1000 };
}

export function mintRememberToken({ itchUserId, itchUsername, playFabId, dev = false }) {
  if (!privateKeyObj) throw new Error("Signing key not configured");

  const nowSeconds = Math.floor(Date.now() / 1000);
  const itchUserIdString = String(itchUserId ?? "");
  const frogUserId = crypto.createHash("sha256").update(`frogwars:${itchUserIdString}`).digest("hex").slice(0, 24);

  const header = { alg: "RS256", typ: "JWT" };
  const payload = {
    v: TOKEN_VERSION,
    purpose: "remember-login",
    sub: frogUserId,
    itch: itchUserIdString,
    itchUsername: itchUsername ? String(itchUsername) : null,
    pf: playFabId ? String(playFabId) : null,
    own: true,
    dev: Boolean(dev),
    iat: nowSeconds,
    exp: nowSeconds + REMEMBER_LOGIN_SECONDS
  };

  const signingInput = `${base64UrlEncode(JSON.stringify(header))}.${base64UrlEncode(JSON.stringify(payload))}`;
  const signature = crypto.sign("RSA-SHA256", Buffer.from(signingInput, "utf8"), privateKeyObj);
  const token = `${signingInput}.${base64UrlEncode(signature)}`;

  return { token, payload, expiresAtUnixMs: payload.exp * 1000 };
}

export function mintSignedPayload(fields, ttlSeconds = 86400) {
  if (!privateKeyObj) throw new Error("Signing key not configured");
  const nowSeconds = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const payload = {
    v: TOKEN_VERSION,
    ...(fields ?? {}),
    iat: nowSeconds,
    exp: nowSeconds + Math.max(60, Number.parseInt(ttlSeconds, 10) || 86400)
  };
  const signingInput = `${base64UrlEncode(JSON.stringify(header))}.${base64UrlEncode(JSON.stringify(payload))}`;
  const signature = crypto.sign("RSA-SHA256", Buffer.from(signingInput, "utf8"), privateKeyObj);
  return { token: `${signingInput}.${base64UrlEncode(signature)}`, payload, expiresAtUnixMs: payload.exp * 1000 };
}

// Returns { valid, payload, reason }.
export function verifySessionToken(token) {
  if (!privateKeyObj || !publicKeyPem)
    return { valid: false, reason: "not-configured" };

  const text = String(token ?? "").trim();
  if (!text)
    return { valid: false, reason: "missing" };

  const parts = text.split(".");
  if (parts.length !== 3)
    return { valid: false, reason: "malformed" };

  const [headerB64, payloadB64, sigB64] = parts;
  const signingInput = `${headerB64}.${payloadB64}`;

  let signatureOk = false;
  try {
    signatureOk = crypto.verify(
      "RSA-SHA256",
      Buffer.from(signingInput, "utf8"),
      crypto.createPublicKey(publicKeyPem),
      base64UrlToBuffer(sigB64)
    );
  } catch {
    signatureOk = false;
  }
  if (!signatureOk)
    return { valid: false, reason: "bad-signature" };

  let payload;
  try {
    payload = JSON.parse(base64UrlDecodeToString(payloadB64));
  } catch {
    return { valid: false, reason: "bad-payload" };
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== "number" || payload.exp <= nowSeconds)
    return { valid: false, reason: "expired" };

  if (!payload.own)
    return { valid: false, reason: "not-owner" };

  return { valid: true, payload };
}

export function verifyRememberToken(token) {
  const result = verifySessionToken(token);
  if (!result.valid)
    return result;

  if (result.payload?.purpose !== "remember-login")
    return { valid: false, reason: "wrong-purpose" };

  return result;
}

// ---------------------------------------------------------------------------
// itch.io API calls
// ---------------------------------------------------------------------------

async function itchGet(path, accessToken) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), ITCH_API_TIMEOUT_MS);
  try {
    const response = await fetch(`${ITCH_API_BASE}${path}`, {
      method: "GET",
      headers: {
        "Authorization": `Bearer ${accessToken}`,
        "Accept": "application/json",
        "User-Agent": "frog-lobby/1.0"
      },
      signal: controller.signal
    });

    const bodyText = await response.text();
    let body = null;
    if (bodyText) {
      try { body = JSON.parse(bodyText); } catch { body = { raw: bodyText }; }
    }
    return { status: response.status, ok: response.ok, body };
  } finally {
    clearTimeout(timeout);
  }
}

async function fetchItchProfile(accessToken) {
  const res = await itchGet("/profile", accessToken);
  if (!res.ok || !res.body || res.body.errors)
    return null;
  const user = res.body.user ?? res.body;
  if (!user || (user.id == null))
    return null;
  return {
    id: String(user.id),
    username: user.username ?? null,
    displayName: user.display_name ?? user.username ?? null
  };
}

// Preferred ownership check. NOTE: the exact owned-vs-not response shape is
// confirmed in spec task 0.2; this parser is defensive about field names.
// Returns: true | false | null (null = endpoint unavailable/unknown -> use fallback).
async function checkOwnershipEndpoint(accessToken) {
  let res;
  try {
    res = await itchGet(`/games/${encodeURIComponent(ITCH_GAME_ID)}/ownership`, accessToken);
  } catch {
    return null;
  }

  if (res.status === 404)
    return null; // endpoint not available for this token/app -> fall back

  if (!res.ok || !res.body)
    return null;

  if (res.body.errors)
    return false;

  const b = res.body;
  // Be tolerant of possible shapes until 0.2 confirms the canonical one.
  if (typeof b.owns_game === "boolean") return b.owns_game;
  if (typeof b.owns === "boolean") return b.owns;
  if (b.ownership && typeof b.ownership.owns_game === "boolean") return b.ownership.owns_game;
  if (typeof b.has_access === "boolean") return b.has_access;
  // If the endpoint returns an object with download key / purchase evidence:
  if (b.download_key || (Array.isArray(b.purchases) && b.purchases.length > 0)) return true;
  return null; // unknown shape -> fall back to download_keys
}

// Fallback: download_keys lookup honors purchased AND claimed (free friend) keys.
async function checkDownloadKey(accessToken, itchUserId) {
  let res;
  try {
    res = await itchGet(`/games/${encodeURIComponent(ITCH_GAME_ID)}/download_keys?user_id=${encodeURIComponent(itchUserId)}`, accessToken);
  } catch {
    return false;
  }
  if (!res.ok || !res.body)
    return false;
  if (res.body.errors)
    return false; // "no download key found"
  return Boolean(res.body.download_key);
}

// Full verify flow. Returns:
//   { status: "verified", itchUserId, itchUsername }
//   { status: "not-owner", itchUserId, itchUsername }
//   { status: "itch-auth-failed" }   (bad/expired access token)
//   { status: "itch-unavailable" }   (transport/5xx)
export async function verifyItchOwnership(accessToken) {
  const token = String(accessToken ?? "").trim();
  if (!token)
    return { status: "itch-auth-failed" };

  let profile;
  try {
    profile = await fetchItchProfile(token);
  } catch (error) {
    return { status: "itch-unavailable", detail: error.message };
  }
  if (!profile)
    return { status: "itch-auth-failed" };

  let owned = null;
  try {
    owned = await checkOwnershipEndpoint(token);
  } catch {
    owned = null;
  }

  if (owned === null) {
    try {
      owned = await checkDownloadKey(token, profile.id);
    } catch {
      owned = false;
    }
  }

  return {
    status: owned ? "verified" : "not-owner",
    itchUserId: profile.id,
    itchUsername: profile.username
  };
}

// ---------------------------------------------------------------------------
// Request gating
// ---------------------------------------------------------------------------

// Reads a FW token from Authorization: Bearer, body.frogToken, or query.
export function extractFrogToken(req) {
  const auth = req?.headers?.authorization;
  if (typeof auth === "string" && auth.toLowerCase().startsWith("bearer "))
    return auth.slice(7).trim();
  if (typeof req?.body?.frogToken === "string") return req.body.frogToken.trim();
  if (typeof req?.query?.frogToken === "string") return req.query.frogToken.trim();
  return "";
}

function devBypassPresented(req) {
  if (!ITCH_DEV_BYPASS_TOKEN) return false;
  const provided =
    (typeof req?.headers?.["x-frogwars-dev-bypass"] === "string" && req.headers["x-frogwars-dev-bypass"].trim()) ||
    (typeof req?.body?.devBypassToken === "string" && req.body.devBypassToken.trim()) ||
    "";
  // constant-time compare
  if (!provided || provided.length !== ITCH_DEV_BYPASS_TOKEN.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(ITCH_DEV_BYPASS_TOKEN));
  } catch {
    return false;
  }
}

// Express-style guard for gated official endpoints. Returns the decoded payload
// (or a dev/disabled marker) when access is allowed, or null after sending a
// response when blocked. Usage:
//   const session = requireFrogSession(req, res); if (!session) return;
export function requireFrogSession(req, res) {
  if (!isEnforced()) {
    // Gate inactive (disabled or not yet configured) -> allow, existing behavior preserved.
    return { enforced: false, payload: null };
  }

  if (devBypassPresented(req))
    return { enforced: true, dev: true, payload: { dev: true } };

  const token = extractFrogToken(req);
  const result = verifySessionToken(token);
  if (result.valid)
    return { enforced: true, dev: false, payload: result.payload };

  const expired = result.reason === "expired";
  res.status(expired ? 401 : 403).json({
    ok: false,
    accepted: false,
    error: expired
      ? "Session expired. Please login again."
      : "This action requires verified itch.io ownership of Frog Wars.",
    reason: result.reason
  });
  return null;
}

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

// linkAccount is an optional async (itchUserId, itchUsername, playFabId) => void
// used to persist the itch<->PlayFab mapping (e.g. into PlayFab). resolvePlayFabAccount
// is an optional async (itchUserId, itchUsername) => { playFabId, sessionTicket,
// newlyCreated } used to make itch identity resolve to the same PlayFab account on
// every PC. Both are optional so this module has no hard dependency on PlayFab helpers.
export function registerItchOwnershipRoutes(app, options = {}) {
  const { linkAccount = null, resolvePlayFabAccount = null } = options;

  // Expose the public verification key so the Unity build can fetch/bundle it.
  app.get("/auth/itch/public-key", (_req, res) => {
    if (!publicKeyPem)
      return res.status(503).json({ ok: false, error: "Signing key not configured." });
    return res.json({ ok: true, algorithm: "RS256", publicKeyPem });
  });

  app.post("/auth/itch/verify", async (req, res) => {
    if (!isConfigured()) {
      return res.status(503).json({
        ok: false,
        error: `itch ownership is not configured on the backend. Missing: ${missingConfigList().join(", ") || "key"}.`
      });
    }

    const accessToken = String(req.body?.accessToken ?? "").trim();
    if (!accessToken)
      return res.status(400).json({ ok: false, error: "accessToken is required" });

    const requestedPlayFabId = typeof req.body?.playFabId === "string" ? req.body.playFabId.trim() : null;

    let result;
    try {
      result = await verifyItchOwnership(accessToken);
    } catch (error) {
      console.warn(`[itch] ownership verify crashed: ${error.message}`);
      return res.status(502).json({ ok: false, error: "Could not reach itch.io to verify ownership." });
    }

    if (result.status === "itch-auth-failed")
      return res.status(401).json({ ok: false, error: "Could not verify itch.io ownership. Please login again or launch through itch.io." });

    if (result.status === "itch-unavailable")
      return res.status(502).json({ ok: false, error: "Could not reach itch.io to verify ownership. Please try again." });

    if (result.status === "not-owner") {
      console.log(`[itch] verify: itch=${maskId(result.itchUserId)} NOT owner`);
      return res.json({ ok: true, ownershipVerified: false });
    }

    // Verified owner -> resolve the canonical PlayFab account, optionally persist
    // the link, then mint a token whose pf claim matches that account.
    let playFabAccount = null;
    if (typeof resolvePlayFabAccount === "function") {
      try {
        playFabAccount = await resolvePlayFabAccount(result.itchUserId, result.itchUsername);
      } catch (error) {
        console.warn(`[itch] PlayFab account resolve failed: ${error.message}`);
        return res.status(502).json({ ok: false, error: "Could not load your Frog Wars account. Please try again." });
      }
    }

    const playFabId = String(playFabAccount?.playFabId ?? requestedPlayFabId ?? "").trim() || null;

    if (typeof linkAccount === "function") {
      try {
        await linkAccount(result.itchUserId, result.itchUsername, playFabId);
      } catch (error) {
        console.warn(`[itch] account link failed (non-fatal): ${error.message}`);
      }
    }

    const { token, expiresAtUnixMs } = mintSessionToken({
      itchUserId: result.itchUserId,
      playFabId,
      ownershipVerified: true,
      dev: false
    });
    const { token: rememberToken, expiresAtUnixMs: rememberExpiresAtUnixMs } = mintRememberToken({
      itchUserId: result.itchUserId,
      itchUsername: result.itchUsername,
      playFabId,
      dev: false
    });

    console.log(`[itch] verify: itch=${maskId(result.itchUserId)} VERIFIED owner, token ttl ${SESSION_TTL_HOURS}h`);
    return res.json({
      ok: true,
      ownershipVerified: true,
      token,
      expiresAtUnixMs,
      rememberToken,
      rememberExpiresAtUnixMs,
      itchUsername: result.itchUsername ?? null,
      playFabId,
      sessionTicket: playFabAccount?.sessionTicket ?? null,
      playFabNewlyCreated: Boolean(playFabAccount?.newlyCreated)
    });
  });

  // Re-issue a fresh token from a still-valid one (no itch round-trip), as long
  // as the original was issued within the refresh cutoff window.
  app.post("/auth/itch/refresh", (req, res) => {
    if (!isConfigured())
      return res.status(503).json({ ok: false, error: "itch ownership is not configured on the backend." });

    const token = String(req.body?.token ?? extractFrogToken(req) ?? "").trim();
    const result = verifySessionToken(token);
    if (!result.valid)
      return res.status(401).json({ ok: false, error: "Session expired. Please login again.", reason: result.reason });

    const nowSeconds = Math.floor(Date.now() / 1000);
    const issuedAt = typeof result.payload.iat === "number" ? result.payload.iat : nowSeconds;
    if (nowSeconds - issuedAt > SESSION_REFRESH_CUTOFF_SECONDS)
      return res.status(401).json({ ok: false, error: "Session expired. Please login again.", reason: "refresh-cutoff" });

    const { token: fresh, expiresAtUnixMs } = mintSessionToken({
      itchUserId: result.payload.itch,
      playFabId: result.payload.pf,
      ownershipVerified: true,
      dev: Boolean(result.payload.dev)
    });
    return res.json({ ok: true, token: fresh, expiresAtUnixMs });
  });

  // Mint a fresh short-lived Frog Wars session from a remembered-login token.
  // The remember token itself is not renewed here; after its absolute expiry the
  // player must perform the browser OAuth flow again.
  app.post("/auth/itch/remember", async (req, res) => {
    if (!isConfigured())
      return res.status(503).json({ ok: false, error: "itch ownership is not configured on the backend." });

    const token = String(req.body?.rememberToken ?? "").trim();
    const result = verifyRememberToken(token);
    if (!result.valid)
      return res.status(401).json({ ok: false, error: "Remembered login expired. Please login again.", reason: result.reason });

    let playFabAccount = null;
    if (typeof resolvePlayFabAccount === "function") {
      try {
        playFabAccount = await resolvePlayFabAccount(result.payload.itch, result.payload.itchUsername);
      } catch (error) {
        console.warn(`[itch] remembered PlayFab account resolve failed: ${error.message}`);
        return res.status(502).json({ ok: false, error: "Could not load your Frog Wars account. Please try again." });
      }
    }

    const playFabId = String(playFabAccount?.playFabId ?? result.payload.pf ?? "").trim() || null;
    const { token: fresh, expiresAtUnixMs } = mintSessionToken({
      itchUserId: result.payload.itch,
      playFabId,
      ownershipVerified: true,
      dev: Boolean(result.payload.dev)
    });

    return res.json({
      ok: true,
      ownershipVerified: true,
      token: fresh,
      expiresAtUnixMs,
      itchUsername: result.payload.itchUsername ?? null,
      playFabId,
      sessionTicket: playFabAccount?.sessionTicket ?? null,
      playFabNewlyCreated: Boolean(playFabAccount?.newlyCreated),
      rememberExpiresAtUnixMs: result.payload.exp * 1000
    });
  });

  // Dev-only token mint, impossible without the server-side ITCH_DEV_BYPASS_TOKEN.
  app.post("/auth/itch/dev-token", (req, res) => {
    if (!isConfigured())
      return res.status(503).json({ ok: false, error: "itch ownership is not configured on the backend." });
    if (!devBypassPresented(req))
      return res.status(403).json({ ok: false, error: "Dev bypass not authorized." });

    const { token, expiresAtUnixMs } = mintSessionToken({
      itchUserId: `dev-${Date.now()}`,
      playFabId: typeof req.body?.playFabId === "string" ? req.body.playFabId.trim() : null,
      ownershipVerified: true,
      dev: true
    });
    return res.json({ ok: true, token, expiresAtUnixMs, dev: true });
  });
}
