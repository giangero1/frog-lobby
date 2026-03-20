import express from "express";
import cors from "cors";
import crypto from "crypto";

const app = express();
app.use(cors());
app.use(express.json());

const rooms = new Map();
const HEARTBEAT_TIMEOUT_MS = 60 * 1000;
const SESSION_TIMEOUT_MS = 2 * 60 * 1000;

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
    hostCandidates
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
      natTraversalEnabled: Boolean(room.natTraversalEnabled)
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

  const now = Date.now();
  const session = {
    sessionId: createSessionId(),
    createdAt: now,
    lastSeen: now,
    clientCandidates: [],
    hostCandidates: Array.isArray(room.hostCandidates) && room.hostCandidates.length > 0
      ? room.hostCandidates
      : buildPublishedCandidate(room),
    hostReady: false
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

app.get("/rooms/:roomId/pending-sessions", (req, res) => {
  const room = getRoom(req.params.roomId);
  if (!room) return res.sendStatus(404);

  const sessions = [];
  for (const session of room.joinSessions.values()) {
    if (!Array.isArray(session.clientCandidates) || session.clientCandidates.length === 0) continue;
    if (session.hostReady) continue;

    sessions.push({
      sessionId: session.sessionId,
      createdAtUnixMs: session.createdAt,
      expiresAtUnixMs: session.lastSeen + SESSION_TIMEOUT_MS,
      clientCandidates: session.clientCandidates,
      hostCandidates: Array.isArray(session.hostCandidates) && session.hostCandidates.length > 0
        ? session.hostCandidates
        : buildPublishedCandidate(room)
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

app.get("/rooms/:roomId/sessions/:sessionId", (req, res) => {
  const room = getRoom(req.params.roomId);
  if (!room) return res.sendStatus(404);

  const session = getSession(room, req.params.sessionId);
  if (!session) return res.sendStatus(404);

  return res.json({
    sessionId: session.sessionId,
    roomId: room.roomId,
    hostReady: Boolean(session.hostReady),
    clientCandidatesSubmitted: Array.isArray(session.clientCandidates) && session.clientCandidates.length > 0,
    hostCandidates: Array.isArray(session.hostCandidates) && session.hostCandidates.length > 0
      ? session.hostCandidates
      : buildPublishedCandidate(room),
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
