import express from "express";
import cors from "cors";

const app = express();
app.use(cors());                // allows Unity clients to call from any origin
app.use(express.json());

const rooms = new Map();
const HEARTBEAT_TIMEOUT_MS = 60 * 1000;

function pruneRooms() {
  const now = Date.now();
  for (const [id, room] of rooms) {
    if (now - room.lastSeen > HEARTBEAT_TIMEOUT_MS) {
      rooms.delete(id);
    }
  }
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
    upnpSucceeded = false
  } = req.body;

  if (!roomId) {
    return res.status(400).json({ error: "roomId required" });
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
    lastSeen: Date.now()
  });

  return res.sendStatus(204);
});

app.get("/rooms", (_req, res) => {
  pruneRooms();
  const payload = Array.from(rooms.values()).map(
    ({ lastSeen, ...room }) => room
  );
  res.json(payload);
});

app.put("/rooms/:roomId/heartbeat", (req, res) => {
  const entry = rooms.get(req.params.roomId);
  if (!entry) {
    return res.sendStatus(404);
  }
  entry.lastSeen = Date.now();
  rooms.set(req.params.roomId, entry);
  res.sendStatus(204);
});

app.delete("/rooms/:roomId", (req, res) => {
  rooms.delete(req.params.roomId);
  res.sendStatus(204);
});

// Render injects PORT; fall back to 7070 when running locally
const port = process.env.PORT || 7070;
app.listen(port, () => {
  console.log(`Lobby server listening on ${port}`);
});
