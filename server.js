import express from "express";
import cors from "cors";
import crypto from "crypto";

const app = express();
app.set("trust proxy", true);
app.use(cors());
app.use(express.json());

const rooms = new Map();
const HEARTBEAT_TIMEOUT_MS = 60 * 1000;
const SESSION_TIMEOUT_MS = 2 * 60 * 1000;
const EDGEGAP_LOBBY_URL = (process.env.EDGEGAP_LOBBY_URL ?? "").trim();
const RELAY_REGION = (process.env.UNITY_RELAY_REGION ?? process.env.EDGEGAP_REGION ?? "").trim() || null;
const UNITY_RELAY_REGION_AUTO_GEO = isTruthy(process.env.UNITY_RELAY_REGION_AUTO_GEO);
const GEO_LOOKUP_URL_TEMPLATE = (process.env.RELAY_REGION_GEO_LOOKUP_URL_TEMPLATE ?? "https://ipinfo.io/{ip}/country").trim();
const GEO_LOOKUP_TIMEOUT_MS = Math.max(500, Number.parseInt(process.env.RELAY_REGION_GEO_LOOKUP_TIMEOUT_MS ?? "1500", 10) || 1500);
const GEO_LOOKUP_CACHE_TTL_MS = Math.max(60_000, Number.parseInt(process.env.RELAY_REGION_GEO_CACHE_SECONDS ?? "21600", 10) * 1000 || 21_600_000);
const RELAY_PROVIDER_SETTING = normalizeRelayProvider(process.env.RELAY_PROVIDER ?? process.env.DEFAULT_RELAY_PROVIDER ?? "");
const UNITY_RELAY_ENABLED = isTruthy(process.env.UNITY_RELAY_ENABLED) || RELAY_PROVIDER_SETTING === "unity";
const EDGEGAP_RELAY_ENABLED = EDGEGAP_LOBBY_URL.length > 0;
const RELAY_PROVIDER = RELAY_PROVIDER_SETTING || (UNITY_RELAY_ENABLED ? "unity" : (EDGEGAP_RELAY_ENABLED ? "edgegap" : null));
const RELAY_ENABLED = RELAY_PROVIDER === "unity"
  ? UNITY_RELAY_ENABLED
  : RELAY_PROVIDER === "edgegap" && EDGEGAP_RELAY_ENABLED;
const LEGACY_DIRECT_ENABLED = (process.env.LEGACY_DIRECT_ENABLED ?? "true").toLowerCase() !== "false";
const CONFIGURED_DEFAULT_INTERNET_MODE = (process.env.DEFAULT_INTERNET_MODE ?? "").trim().toLowerCase();
const DEFAULT_INTERNET_MODE = CONFIGURED_DEFAULT_INTERNET_MODE === "relay" && RELAY_ENABLED
  ? "relay"
  : CONFIGURED_DEFAULT_INTERNET_MODE === "direct"
    ? "direct"
    : (RELAY_ENABLED ? "relay" : "direct");
const RELAY_LOBBY_WAIT_TIMEOUT_SECONDS = Math.max(5, Number.parseInt(process.env.RELAY_LOBBY_WAIT_TIMEOUT_SECONDS ?? "30", 10) || 30);
const geoLookupCache = new Map();

const EUROPE_CENTRAL_RELAY_COUNTRIES = new Set([
  "AL", "AT", "BA", "BG", "CH", "CZ", "DE", "GR", "HR", "HU", "IT", "LI",
  "MD", "ME", "MK", "PL", "RO", "RS", "SI", "SK", "TR", "UA", "XK"
]);
const EUROPE_WEST_RELAY_COUNTRIES = new Set([
  "AD", "BE", "ES", "FR", "GB", "IE", "LU", "MC", "NL", "PT", "UK"
]);
const EUROPE_NORTH_RELAY_COUNTRIES = new Set([
  "DK", "EE", "FI", "IS", "LT", "LV", "NO", "SE"
]);
const ASIA_NORTHEAST_RELAY_COUNTRIES = new Set(["HK", "JP", "KR", "MO", "MN", "TW"]);
const ASIA_SOUTH_RELAY_COUNTRIES = new Set([
  "AF", "BD", "BH", "BT", "IN", "IR", "KW", "LK", "MV", "NP", "OM", "PK",
  "QA", "SA", "AE", "YE"
]);
const ASIA_SOUTHEAST_RELAY_COUNTRIES = new Set(["BN", "KH", "ID", "LA", "MY", "MM", "PH", "SG", "TH", "VN"]);
const AUSTRALIA_RELAY_COUNTRIES = new Set(["AU", "FJ", "NZ", "PG"]);
const SOUTH_AMERICA_RELAY_COUNTRIES = new Set(["AR", "BO", "BR", "CL", "CO", "EC", "GY", "PE", "PY", "SR", "UY", "VE"]);
const NORTH_AMERICA_RELAY_COUNTRIES = new Set(["CA", "MX", "US"]);
const MENA_EUROPE_RELAY_COUNTRIES = new Set(["CY", "DZ", "EG", "IL", "JO", "LB", "LY", "MA", "PS", "SY", "TN"]);

function isTruthy(value) {
  return ["1", "true", "yes", "y", "on"].includes(String(value ?? "").trim().toLowerCase());
}

function normalizeRelayProvider(provider) {
  const normalized = String(provider ?? "").trim().toLowerCase();
  if (normalized === "unity-relay") return "unity";
  if (normalized === "unity" || normalized === "edgegap") return normalized;
  return "";
}

function getRequesterIp(req) {
  const forwarded = req?.headers?.["x-forwarded-for"];
  const forwardedValue = Array.isArray(forwarded) ? forwarded[0] : forwarded;
  const firstForwardedIp = typeof forwardedValue === "string"
    ? forwardedValue.split(",").map(part => part.trim()).find(Boolean)
    : "";
  return normalizeIp(firstForwardedIp || req?.ip || req?.socket?.remoteAddress || "");
}

function normalizeIp(raw) {
  let value = String(raw ?? "").trim();
  if (!value) return "";
  if (value.startsWith("::ffff:"))
    value = value.slice("::ffff:".length);
  if (value.startsWith("[") && value.includes("]"))
    value = value.slice(1, value.indexOf("]"));
  if (/^\d{1,3}(?:\.\d{1,3}){3}:\d+$/.test(value))
    value = value.slice(0, value.lastIndexOf(":"));
  return value;
}

function isPrivateOrLocalIp(ip) {
  if (!ip) return true;
  const value = ip.toLowerCase();
  if (value === "::1" || value === "localhost")
    return true;
  if (value.startsWith("fc") || value.startsWith("fd") || value.startsWith("fe80:"))
    return true;

  const parts = value.split(".").map(part => Number.parseInt(part, 10));
  if (parts.length !== 4 || parts.some(part => Number.isNaN(part)))
    return false;

  const [a, b] = parts;
  return a === 10 ||
    a === 127 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254);
}

function maskIpPrefix(ip) {
  if (!ip) return null;
  if (isPrivateOrLocalIp(ip)) return "private";

  const ipv4 = ip.split(".");
  if (ipv4.length === 4 && ipv4.every(part => /^\d{1,3}$/.test(part)))
    return `${ipv4[0]}.${ipv4[1]}.x.x`;

  if (ip.includes(":")) {
    const groups = ip.split(":").filter(Boolean);
    return groups.length > 0 ? `${groups.slice(0, 4).join(":")}::/64` : "ipv6";
  }

  return "unknown";
}

function normalizeCountryCode(raw) {
  const match = String(raw ?? "").trim().toUpperCase().match(/[A-Z]{2}/);
  return match ? match[0] : null;
}

function parseCountryLookupResponse(raw) {
  const text = String(raw ?? "").trim();
  if (!text) return null;

  if (text.startsWith("{")) {
    try {
      const parsed = JSON.parse(text);
      return normalizeCountryCode(parsed.country ?? parsed.countryCode ?? parsed.country_code);
    } catch {
      return null;
    }
  }

  return normalizeCountryCode(text);
}

function mapCountryToRelayRegion(countryCode) {
  const country = normalizeCountryCode(countryCode);
  if (!country) return null;
  if (EUROPE_CENTRAL_RELAY_COUNTRIES.has(country)) return "europe-central2";
  if (EUROPE_WEST_RELAY_COUNTRIES.has(country)) return "europe-west4";
  if (EUROPE_NORTH_RELAY_COUNTRIES.has(country)) return "europe-north1";
  if (MENA_EUROPE_RELAY_COUNTRIES.has(country)) return "europe-central2";
  if (NORTH_AMERICA_RELAY_COUNTRIES.has(country)) return "us-central1";
  if (SOUTH_AMERICA_RELAY_COUNTRIES.has(country)) return "southamerica-east1";
  if (ASIA_NORTHEAST_RELAY_COUNTRIES.has(country)) return "asia-northeast1";
  if (ASIA_SOUTH_RELAY_COUNTRIES.has(country)) return "asia-south1";
  if (ASIA_SOUTHEAST_RELAY_COUNTRIES.has(country)) return "asia-southeast1";
  if (AUSTRALIA_RELAY_COUNTRIES.has(country)) return "australia-southeast1";
  return null;
}

async function lookupCountryForIp(ip) {
  if (!ip || isPrivateOrLocalIp(ip) || !GEO_LOOKUP_URL_TEMPLATE)
    return null;

  const now = Date.now();
  const cached = geoLookupCache.get(ip);
  if (cached && cached.expiresAt > now)
    return cached.country;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), GEO_LOOKUP_TIMEOUT_MS);
  try {
    const url = GEO_LOOKUP_URL_TEMPLATE.replace("{ip}", encodeURIComponent(ip));
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { "user-agent": "frog-lobby/1.0" }
    });
    if (!response.ok)
      throw new Error(`geo lookup returned ${response.status}`);

    const country = parseCountryLookupResponse(await response.text());
    geoLookupCache.set(ip, { country, expiresAt: now + GEO_LOOKUP_CACHE_TTL_MS });
    return country;
  } finally {
    clearTimeout(timeout);
  }
}

async function resolveRelayRegionForRequest(req) {
  const ip = getRequesterIp(req);
  const ipPrefix = maskIpPrefix(ip);

  if (RELAY_REGION) {
    return {
      region: RELAY_REGION,
      source: "forced",
      country: null,
      ipPrefix
    };
  }

  if (!UNITY_RELAY_REGION_AUTO_GEO) {
    return {
      region: null,
      source: "unity-auto",
      country: null,
      ipPrefix
    };
  }

  try {
    const country = await lookupCountryForIp(ip);
    const region = mapCountryToRelayRegion(country);
    if (region) {
      return {
        region,
        source: "geo-ip",
        country,
        ipPrefix
      };
    }

    return {
      region: null,
      source: "unity-auto",
      country,
      ipPrefix
    };
  } catch (error) {
    if (isTruthy(process.env.RELAY_REGION_GEO_DEBUG))
      console.warn(`[config] Geo relay region lookup failed for ${ipPrefix ?? "unknown"}: ${error.message}`);

    return {
      region: null,
      source: "unity-auto",
      country: null,
      ipPrefix
    };
  }
}

function pruneRooms() {
  const now = Date.now();
  for (const [id, room] of rooms) {
    if (now - room.lastSeen > HEARTBEAT_TIMEOUT_MS) {
      rooms.delete(id);
      continue;
    }

    pruneSessions(room, now);
  }
}

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, "sha512").toString("hex");
}

function createSessionId() {
  return crypto.randomBytes(16).toString("hex");
}

function pruneSessions(room, now = Date.now()) {
  const sessions = room.joinSessions;
  if (!(sessions instanceof Map)) return;

  for (const [sessionId, session] of sessions) {
    if (now - session.lastSeen > SESSION_TIMEOUT_MS) {
      sessions.delete(sessionId);
    }
  }
}

function normalizeCandidates(candidates) {
  if (!Array.isArray(candidates)) return [];

  return candidates
    .filter(candidate =>
      candidate &&
      typeof candidate.address === "string" &&
      candidate.address.length > 0 &&
      Number.isInteger(candidate.port) &&
      candidate.port > 0 &&
      candidate.port <= 65535
    )
    .map(candidate => ({
      kind: typeof candidate.kind === "string" ? candidate.kind : "unknown",
      transport: typeof candidate.transport === "string" ? candidate.transport : "udp",
      address: candidate.address,
      port: candidate.port,
      source: typeof candidate.source === "string" ? candidate.source : null,
      updatedAt: Date.now()
    }));
}

function normalizeSingleCandidate(candidate) {
  const normalized = normalizeCandidates(candidate ? [candidate] : []);
  return normalized.length > 0 ? normalized[0] : null;
}

function normalizeInternetMode(mode) {
  return typeof mode === "string" && mode.toLowerCase() === "relay" ? "relay" : "direct";
}

function getRoomInternetMode(room) {
  return normalizeInternetMode(room?.internetMode ?? DEFAULT_INTERNET_MODE);
}

function buildPublishedCandidate(room) {
  if (!room.externalAddress || !room.externalPort) return [];

  return [{
    kind: "published",
    transport: room.transportType === "telepathy" ? "tcp" : "udp",
    address: room.externalAddress,
    port: room.externalPort,
    source: "room"
  }];
}

function buildJoinResponse(room, session) {
  const internetMode = getRoomInternetMode(room);
  return {
    roomId: room.roomId,
    roomName: room.roomName,
    hostPlayer: room.hostPlayer,
    externalAddress: room.externalAddress,
    externalPort: room.externalPort,
    upnpSucceeded: room.upnpSucceeded,
    regionLabel: room.regionLabel ?? null,
    transportType: room.transportType ?? null,
    natTraversalEnabled: Boolean(room.natTraversalEnabled),
    internetMode,
    relayProvider: room.relayProvider ?? (internetMode === "relay" ? RELAY_PROVIDER : null),
    relayLobbyId: room.relayLobbyId ?? null,
    relayJoinCode: room.relayJoinCode ?? (room.relayProvider === "unity" ? room.relayLobbyId ?? null : null),
    relayLobbyUrl: room.relayLobbyUrl ?? (internetMode === "relay" && RELAY_PROVIDER === "edgegap" ? EDGEGAP_LOBBY_URL || null : null),
    relayRegion: room.relayRegion ?? RELAY_REGION,
    relayReady: Boolean(room.relayReady),
    hostCandidates: Array.isArray(session?.hostCandidates) && session.hostCandidates.length > 0
      ? session.hostCandidates
      : (Array.isArray(room.hostCandidates) && room.hostCandidates.length > 0
        ? room.hostCandidates
        : buildPublishedCandidate(room)),
    sessionId: session?.sessionId ?? null,
    sessionExpiresAtUnixMs: session ? session.lastSeen + SESSION_TIMEOUT_MS : null
  };
}

function getRoom(roomId) {
  pruneRooms();
  return rooms.get(roomId) ?? null;
}

function getSession(room, sessionId) {
  pruneSessions(room);
  return room.joinSessions?.get(sessionId) ?? null;
}

async function buildConfigPayload(req = null) {
  const relayRegionSelection = await resolveRelayRegionForRequest(req);
  return {
    defaultInternetMode: DEFAULT_INTERNET_MODE,
    relayEnabled: RELAY_ENABLED,
    legacyDirectEnabled: LEGACY_DIRECT_ENABLED,
    relayProvider: RELAY_PROVIDER,
    relayLobbyUrl: RELAY_PROVIDER === "edgegap" ? EDGEGAP_LOBBY_URL || null : null,
    relayRegion: relayRegionSelection.region,
    relayRegionSource: relayRegionSelection.source,
    relayRegionCountry: relayRegionSelection.country,
    relayRegionIpPrefix: relayRegionSelection.ipPrefix,
    unityRelayEnabled: RELAY_PROVIDER === "unity" && RELAY_ENABLED,
    relayLobbyWaitTimeoutSeconds: RELAY_LOBBY_WAIT_TIMEOUT_SECONDS
  };
}

app.get("/health", async (req, res) => {
  pruneRooms();
  let joinSessionCount = 0;
  for (const room of rooms.values()) {
    if (room.joinSessions instanceof Map)
      joinSessionCount += room.joinSessions.size;
  }

  return res.json({
    ok: true,
    service: "frog-lobby",
    traversalEnabled: true,
    ...(await buildConfigPayload(req)),
    roomCount: rooms.size,
    joinSessionCount,
    nowUnixMs: Date.now()
  });
});

app.get("/config", async (req, res) => {
  return res.json(await buildConfigPayload(req));
});

app.post("/rooms", (req, res) => {
  const {
    roomId,
    roomName,
    hostPlayer,
    externalAddress,
    externalPort,
    maxPlayers,
    currentPlayers = 1,
    upnpSucceeded = false,
    password,
    regionLabel,
    transportType,
    natTraversalEnabled = false,
    hostCandidates,
    internetMode,
    relayProvider,
    relayLobbyId,
    relayJoinCode,
    relayLobbyUrl,
    relayRegion,
    relayReady = false
  } = req.body;

  if (!roomId) return res.status(400).json({ error: "roomId required" });

  let passwordSalt = null;
  let passwordHash = null;
  if (password && password.length > 0) {
    passwordSalt = crypto.randomBytes(16).toString("hex");
    passwordHash = hashPassword(password, passwordSalt);
  }

  const publishedRelayProvider = normalizeRelayProvider(relayProvider) || RELAY_PROVIDER;
  const publishedRelayLobbyId = typeof relayLobbyId === "string" ? relayLobbyId : null;
  const publishedRelayJoinCode = typeof relayJoinCode === "string"
    ? relayJoinCode
    : (publishedRelayProvider === "unity" ? publishedRelayLobbyId : null);

  rooms.set(roomId, {
    roomId,
    roomName,
    hostPlayer,
    externalAddress,
    externalPort,
    maxPlayers,
    currentPlayers,
    upnpSucceeded,
    regionLabel,
    transportType,
    natTraversalEnabled,
    hostCandidates: normalizeCandidates(hostCandidates),
    internetMode: normalizeInternetMode(internetMode),
    relayProvider: publishedRelayProvider,
    relayLobbyId: publishedRelayLobbyId,
    relayJoinCode: publishedRelayJoinCode,
    relayLobbyUrl: typeof relayLobbyUrl === "string" ? relayLobbyUrl : (RELAY_PROVIDER === "edgegap" ? EDGEGAP_LOBBY_URL || null : null),
    relayRegion: typeof relayRegion === "string" && relayRegion.length > 0 ? relayRegion : RELAY_REGION,
    relayReady: Boolean(relayReady),
    passwordHash,
    passwordSalt,
    lastSeen: Date.now(),
    joinSessions: new Map()
  });

  return res.sendStatus(204);
});

app.get("/rooms", (_req, res) => {
  pruneRooms();
  const payload = [];
  for (const room of rooms.values()) {
    const internetMode = getRoomInternetMode(room);
    payload.push({
      roomId: room.roomId,
      roomName: room.roomName,
      hostPlayer: room.hostPlayer,
      externalAddress: room.externalAddress,
      externalPort: room.externalPort,
      maxPlayers: room.maxPlayers,
      currentPlayers: room.currentPlayers,
      upnpSucceeded: room.upnpSucceeded,
      requiresPassword: Boolean(room.passwordHash),
      regionLabel: room.regionLabel ?? null,
      transportType: room.transportType ?? null,
      natTraversalEnabled: Boolean(room.natTraversalEnabled),
      internetMode,
      relayProvider: room.relayProvider ?? (internetMode === "relay" ? RELAY_PROVIDER : null),
      relayLobbyId: room.relayLobbyId ?? null,
      relayJoinCode: room.relayJoinCode ?? (room.relayProvider === "unity" ? room.relayLobbyId ?? null : null),
      relayLobbyUrl: room.relayLobbyUrl ?? (internetMode === "relay" && RELAY_PROVIDER === "edgegap" ? EDGEGAP_LOBBY_URL || null : null),
      relayRegion: room.relayRegion ?? RELAY_REGION,
      relayReady: Boolean(room.relayReady)
    });
  }
  res.json(payload);
});

app.post("/rooms/:roomId/join", (req, res) => {
  const room = getRoom(req.params.roomId);
  if (!room) return res.sendStatus(404);

  if (room.passwordHash) {
    const provided = req.body?.password ?? "";
    const hashed = hashPassword(provided, room.passwordSalt);
    if (hashed !== room.passwordHash) return res.sendStatus(401);
  }

  if (getRoomInternetMode(room) === "relay") {
    room.lastSeen = Date.now();
    rooms.set(room.roomId, room);
    return res.json(buildJoinResponse(room, null));
  }

  const now = Date.now();
  const session = {
    sessionId: createSessionId(),
    createdAt: now,
    lastSeen: now,
    clientCandidates: [],
    hostCandidates: Array.isArray(room.hostCandidates) && room.hostCandidates.length > 0
      ? room.hostCandidates
      : buildPublishedCandidate(room),
    hostReady: false,
    controllingRole: "host",
    clientObservedHostCandidate: null,
    selectedHostCandidate: null,
    selectedClientCandidate: null,
    nominated: false,
    nominatedBy: null,
    nominatedAtUnixMs: null
  };

  room.joinSessions.set(session.sessionId, session);

  return res.json(buildJoinResponse(room, session));
});

app.post("/rooms/:roomId/sessions/:sessionId/client-candidates", (req, res) => {
  const room = getRoom(req.params.roomId);
  if (!room) return res.sendStatus(404);

  const session = getSession(room, req.params.sessionId);
  if (!session) return res.sendStatus(404);

  session.clientCandidates = normalizeCandidates(req.body?.candidates);
  session.lastSeen = Date.now();
  room.joinSessions.set(session.sessionId, session);
  return res.sendStatus(204);
});

app.post("/rooms/:roomId/sessions/:sessionId/client-observation", (req, res) => {
  const room = getRoom(req.params.roomId);
  if (!room) return res.sendStatus(404);

  const session = getSession(room, req.params.sessionId);
  if (!session) return res.sendStatus(404);

  const observedHostCandidate = normalizeSingleCandidate(req.body?.observedHostCandidate);
  const selectedClientCandidate = normalizeSingleCandidate(req.body?.selectedClientCandidate);
  if (observedHostCandidate) session.clientObservedHostCandidate = observedHostCandidate;
  if (selectedClientCandidate) session.selectedClientCandidate = selectedClientCandidate;
  session.lastSeen = Date.now();
  room.joinSessions.set(session.sessionId, session);
  return res.sendStatus(204);
});

app.get("/rooms/:roomId/pending-sessions", (req, res) => {
  const room = getRoom(req.params.roomId);
  if (!room) return res.sendStatus(404);

  if (getRoomInternetMode(room) === "relay")
    return res.json({ sessions: [] });

  const sessions = [];
  for (const session of room.joinSessions.values()) {
    if (!Array.isArray(session.clientCandidates) || session.clientCandidates.length === 0) continue;
    if (session.nominated) continue;

    sessions.push({
      sessionId: session.sessionId,
      createdAtUnixMs: session.createdAt,
      expiresAtUnixMs: session.lastSeen + SESSION_TIMEOUT_MS,
      hostReady: Boolean(session.hostReady),
      controllingRole: session.controllingRole ?? "host",
      clientCandidates: session.clientCandidates,
      hostCandidates: Array.isArray(session.hostCandidates) && session.hostCandidates.length > 0
        ? session.hostCandidates
        : buildPublishedCandidate(room),
      clientObservedHostCandidate: session.clientObservedHostCandidate ?? null,
      selectedHostCandidate: session.selectedHostCandidate ?? null,
      selectedClientCandidate: session.selectedClientCandidate ?? null,
      nominated: Boolean(session.nominated)
    });
  }

  return res.json({ sessions });
});

app.post("/rooms/:roomId/sessions/:sessionId/host-ready", (req, res) => {
  const room = getRoom(req.params.roomId);
  if (!room) return res.sendStatus(404);

  const session = getSession(room, req.params.sessionId);
  if (!session) return res.sendStatus(404);

  const hostCandidates = normalizeCandidates(req.body?.hostCandidates);
  if (hostCandidates.length > 0) {
    session.hostCandidates = hostCandidates;
    room.hostCandidates = hostCandidates;
  }

  session.hostReady = true;
  session.lastSeen = Date.now();
  room.joinSessions.set(session.sessionId, session);
  return res.sendStatus(204);
});

app.post("/rooms/:roomId/sessions/:sessionId/nominate", (req, res) => {
  const room = getRoom(req.params.roomId);
  if (!room) return res.sendStatus(404);

  const session = getSession(room, req.params.sessionId);
  if (!session) return res.sendStatus(404);

  const selectedHostCandidate = normalizeSingleCandidate(req.body?.selectedHostCandidate);
  const selectedClientCandidate = normalizeSingleCandidate(req.body?.selectedClientCandidate);
  if (!selectedHostCandidate || !selectedClientCandidate) {
    return res.status(400).json({ error: "selectedHostCandidate and selectedClientCandidate are required" });
  }

  session.selectedHostCandidate = selectedHostCandidate;
  session.selectedClientCandidate = selectedClientCandidate;
  session.nominated = true;
  session.nominatedBy = "host";
  session.nominatedAtUnixMs = Date.now();
  session.hostReady = true;
  session.lastSeen = Date.now();
  room.joinSessions.set(session.sessionId, session);
  return res.sendStatus(204);
});

app.get("/rooms/:roomId/sessions/:sessionId", (req, res) => {
  const room = getRoom(req.params.roomId);
  if (!room) return res.sendStatus(404);

  const session = getSession(room, req.params.sessionId);
  if (!session) return res.sendStatus(404);

  return res.json({
    sessionId: session.sessionId,
    roomId: room.roomId,
    hostReady: Boolean(session.hostReady),
    controllingRole: session.controllingRole ?? "host",
    clientCandidatesSubmitted: Array.isArray(session.clientCandidates) && session.clientCandidates.length > 0,
    hostCandidates: Array.isArray(session.hostCandidates) && session.hostCandidates.length > 0
      ? session.hostCandidates
      : buildPublishedCandidate(room),
    clientObservedHostCandidate: session.clientObservedHostCandidate ?? null,
    selectedHostCandidate: session.selectedHostCandidate ?? null,
    selectedClientCandidate: session.selectedClientCandidate ?? null,
    nominated: Boolean(session.nominated),
    nominatedBy: session.nominatedBy ?? null,
    nominatedAtUnixMs: session.nominatedAtUnixMs ?? null,
    createdAtUnixMs: session.createdAt,
    expiresAtUnixMs: session.lastSeen + SESSION_TIMEOUT_MS
  });
});

app.put("/rooms/:roomId/heartbeat", (req, res) => {
  const room = getRoom(req.params.roomId);
  if (!room) return res.sendStatus(404);

  if (typeof req.body?.currentPlayers === "number") room.currentPlayers = req.body.currentPlayers;
  if (typeof req.body?.externalAddress === "string" && req.body.externalAddress.length > 0) room.externalAddress = req.body.externalAddress;
  if (Number.isInteger(req.body?.externalPort) && req.body.externalPort > 0 && req.body.externalPort <= 65535) room.externalPort = req.body.externalPort;
  if (typeof req.body?.upnpSucceeded === "boolean") room.upnpSucceeded = req.body.upnpSucceeded;
  if (typeof req.body?.regionLabel === "string") room.regionLabel = req.body.regionLabel;
  if (typeof req.body?.transportType === "string") room.transportType = req.body.transportType;
  if (typeof req.body?.natTraversalEnabled === "boolean") room.natTraversalEnabled = req.body.natTraversalEnabled;
  if (typeof req.body?.internetMode === "string") room.internetMode = normalizeInternetMode(req.body.internetMode);
  if (typeof req.body?.relayProvider === "string") room.relayProvider = normalizeRelayProvider(req.body.relayProvider) || req.body.relayProvider;
  if (typeof req.body?.relayLobbyId === "string") room.relayLobbyId = req.body.relayLobbyId;
  if (typeof req.body?.relayJoinCode === "string") room.relayJoinCode = req.body.relayJoinCode;
  if (typeof req.body?.relayLobbyUrl === "string") room.relayLobbyUrl = req.body.relayLobbyUrl;
  if (typeof req.body?.relayRegion === "string") room.relayRegion = req.body.relayRegion;
  if (typeof req.body?.relayReady === "boolean") room.relayReady = req.body.relayReady;

  const hostCandidates = normalizeCandidates(req.body?.hostCandidates);
  if (hostCandidates.length > 0)
    room.hostCandidates = hostCandidates;

  room.lastSeen = Date.now();
  rooms.set(room.roomId, room);
  res.sendStatus(204);
});

app.delete("/rooms/:roomId", (req, res) => {
  rooms.delete(req.params.roomId);
  res.sendStatus(204);
});

const port = process.env.PORT || 7070;
app.listen(port, () => console.log(`Lobby server listening on ${port}`));
