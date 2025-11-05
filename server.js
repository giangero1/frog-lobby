import express from "express";
import cors from "cors";
import crypto from "crypto";

const app = express();
app.use(cors());
app.use(express.json());

const rooms = new Map();
const HEARTBEAT_TIMEOUT_MS = 60 * 1000;

function pruneRooms() {
  const now = Date.now();
  for (const [id, room] of rooms) {
    if (now - room.lastSeen > HEARTBEAT_TIMEOUT_MS) rooms.delete(id);
  }
}

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, "sha512").toString("hex");
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
    password
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
    passwordHash,
    passwordSalt,
    lastSeen: Date.now()
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
      maxPlayers: room.maxPlayers,
      currentPlayers: room.currentPlayers,
      upnpSucceeded: room.upnpSucceeded,
      requiresPassword: Boolean(room.passwordHash)
    });
  }
  res.json(payload);
});

app.post("/rooms/:roomId/join", (req, res) => {
  const room = rooms.get(req.params.roomId);
  if (!room) return res.sendStatus(404);

  if (room.passwordHash) {
    const provided = req.body?.password ?? "";
    const hashed = hashPassword(provided, room.passwordSalt);
    if (hashed !== room.passwordHash) return res.sendStatus(401);
  }

  return res.json({
    roomId: room.roomId,
    roomName: room.roomName,
    hostPlayer: room.hostPlayer,
    externalAddress: room.externalAddress,
    externalPort: room.externalPort,
    upnpSucceeded: room.upnpSucceeded
  });
});

app.put("/rooms/:roomId/heartbeat", (req, res) => {
  const room = rooms.get(req.params.roomId);
  if (!room) return res.sendStatus(404);
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
