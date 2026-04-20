import express from "express";
import cors from "cors";
import crypto from "crypto";

const app = express();
app.use(cors());
app.use(express.json());

const rooms = new Map();
const HEARTBEAT_TIMEOUT_MS = 60 * 1000;
const SESSION_TIMEOUT_MS = 2 * 60 * 1000;
const EDGEGAP_LOBBY_URL = (process.env.EDGEGAP_LOBBY_URL ?? "").trim();
const EDGEGAP_REGION = (process.env.EDGEGAP_REGION ?? "").trim() || null;
const RELAY_ENABLED = EDGEGAP_LOBBY_URL.length > 0;
const RELAY_PROVIDER = RELAY_ENABLED ? "edgegap" : null;
const LEGACY_DIRECT_ENABLED = (process.env.LEGACY_DIRECT_ENABLED ?? "true").toLowerCase() !== "false";
const CONFIGURED_DEFAULT_INTERNET_MODE = (process.env.DEFAULT_INTERNET_MODE ?? "").trim().toLowerCase();
const DEFAULT_INTERNET_MODE = CONFIGURED_DEFAULT_INTERNET_MODE || (RELAY_ENABLED ? "relay" : "direct");
const RELAY_LOBBY_WAIT_TIMEOUT_SECONDS = Math.max(5, Number.parseInt(process.env.RELAY_LOBBY_WAIT_TIMEOUT_SECONDS ?? "30", 10) || 30);

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
    relayLobbyUrl: room.relayLobbyUrl ?? (internetMode === "relay" ? EDGEGAP_LOBBY_URL || null : null),
    relayRegion: room.relayRegion ?? EDGEGAP_REGION,
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

function buildConfigPayload() {
  return {
    defaultInternetMode: DEFAULT_INTERNET_MODE,
    relayEnabled: RELAY_ENABLED,
    legacyDirectEnabled: LEGACY_DIRECT_ENABLED,
    relayProvider: RELAY_PROVIDER,
    relayLobbyUrl: EDGEGAP_LOBBY_URL || null,
    relayRegion: EDGEGAP_REGION,
    relayLobbyWaitTimeoutSeconds: RELAY_LOBBY_WAIT_TIMEOUT_SECONDS
  };
}

app.get("/health", (_req, res) => {
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
    ...buildConfigPayload(),
    roomCount: rooms.size,
    joinSessionCount,
    nowUnixMs: Date.now()
  });
});

app.get("/config", (_req, res) => {
  return res.json(buildConfigPayload());
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
    relayProvider: typeof relayProvider === "string" ? relayProvider : RELAY_PROVIDER,
    relayLobbyId: typeof relayLobbyId === "string" ? relayLobbyId : null,
    relayLobbyUrl: typeof relayLobbyUrl === "string" ? relayLobbyUrl : (EDGEGAP_LOBBY_URL || null),
    relayRegion: typeof relayRegion === "string" && relayRegion.length > 0 ? relayRegion : EDGEGAP_REGION,
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
      relayLobbyUrl: room.relayLobbyUrl ?? (internetMode === "relay" ? EDGEGAP_LOBBY_URL || null : null),
      relayRegion: room.relayRegion ?? EDGEGAP_REGION,
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
  if (typeof req.body?.relayProvider === "string") room.relayProvider = req.body.relayProvider;
  if (typeof req.body?.relayLobbyId === "string") room.relayLobbyId = req.body.relayLobbyId;
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
