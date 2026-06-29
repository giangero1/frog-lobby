import express from "express";
import cors from "cors";
import crypto from "crypto";
import { mergeArcadeProgress, normalizeArcadeProgress, normalizeCatalogItem, normalizeEmoteWheel, normalizeHexColor, purchaseDecision, SHOP_SLOTS, updateEmoteWheelSlot, updateMiscellaneousSelection, validateEquipSelection, validateVictoryEmote } from "./shopLogic.js";
import {
  registerItchOwnershipRoutes,
  requireFrogSession,
  mintSignedPayload,
  configPayloadFields as itchConfigPayloadFields,
  configSummaryForLog as itchConfigSummaryForLog
} from "./frogWarsSession.js";

const app = express();
app.set("trust proxy", true);
app.use(cors());
app.use(express.json());

const rooms = new Map();
const arcadeRuns = new Map();
const processedTournamentMatches = new Map();
const HEARTBEAT_TIMEOUT_MS = 60 * 1000;
const SESSION_TIMEOUT_MS = 2 * 60 * 1000;
const PLAYFAB_TITLE_ID = (process.env.PLAYFAB_TITLE_ID ?? "").trim();
const PLAYFAB_SECRET_KEY = (process.env.PLAYFAB_SECRET_KEY ?? "").trim();
const PLAYFAB_API_BASE = PLAYFAB_TITLE_ID ? `https://${PLAYFAB_TITLE_ID}.playfabapi.com` : "";
const SHOP_CURRENCY_CODE = (process.env.SHOP_CURRENCY_CODE ?? "CR").trim().toUpperCase();
const SHOP_CATALOG_VERSION = (process.env.SHOP_CATALOG_VERSION ?? "Cosmetics").trim();
const SHOP_ADMIN_TOKEN = (process.env.SHOP_ADMIN_TOKEN ?? "").trim();
const ACCOUNT_LINK_HMAC_SECRET = (process.env.ACCOUNT_LINK_HMAC_SECRET ?? process.env.FROGWARS_ACCOUNT_LINK_HMAC_SECRET ?? PLAYFAB_SECRET_KEY).trim();
const ARCADE_PROGRESS_KEY = "ArcadeProgressJson";
const SHOP_ITEMS = new Map([
  ["america-first-hat", { displayName: "America First Hat", kind: "cosmetic", slot: "hat", price: 5 }],
  ["shtreimel", { displayName: "Shtreimel", kind: "cosmetic", slot: "hat", price: 8 }],
  ["crusader-helmet", { displayName: "Crusader Helmet", kind: "cosmetic", slot: "hat", price: 12 }],
  ["king-crown", { displayName: "King Crown", kind: "cosmetic", slot: "hat", price: 20 }],
  ["charlie-chaplin-mustache", { displayName: "Charlie Chaplin Mustache", kind: "cosmetic", slot: "miscellaneous", price: 16 }],
  ["wave", { displayName: "Wave", kind: "emote", price: 0 }],
  ["cheer", { displayName: "Cheer", kind: "emote", price: 100 }]
]);
let shopCatalogLastRefresh = 0;
const ARCADE_RUN_TTL_MS = Math.max(60_000, Number.parseInt(process.env.ARCADE_RUN_TTL_SECONDS ?? "1800", 10) * 1000 || 1_800_000);
const ARCADE_SUBMIT_MIN_INTERVAL_MS = Math.max(250, Number.parseInt(process.env.ARCADE_SUBMIT_MIN_INTERVAL_MS ?? "1200", 10) || 1200);
const ARCADE_MAX_DISTANCE_PER_SECOND = Math.max(5, Number.parseFloat(process.env.ARCADE_MAX_DISTANCE_PER_SECOND ?? "35") || 35);
const ARCADE_DISTANCE_GRACE = Math.max(0, Number.parseInt(process.env.ARCADE_DISTANCE_GRACE ?? "250", 10) || 250);
const ARCADE_ABSOLUTE_SCORE_CAP = Math.max(1000, Number.parseInt(process.env.ARCADE_ABSOLUTE_SCORE_CAP ?? "1000000", 10) || 1_000_000);
const TOURNAMENT_CROWN_REWARDS = new Map([
  [1, Math.max(0, Number.parseInt(process.env.TOURNAMENT_CROWNS_FIRST ?? "3", 10) || 3)],
  [2, Math.max(0, Number.parseInt(process.env.TOURNAMENT_CROWNS_SECOND ?? "2", 10) || 2)],
  [3, Math.max(0, Number.parseInt(process.env.TOURNAMENT_CROWNS_THIRD ?? "1", 10) || 1)]
]);
const TOURNAMENT_MATCH_TTL_MS = Math.max(60_000, Number.parseInt(process.env.TOURNAMENT_MATCH_RECEIPT_TTL_SECONDS ?? "86400", 10) * 1000 || 86_400_000);
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

function createReceiptId(prefix) {
  return `${prefix}-${Date.now().toString(36)}-${crypto.randomBytes(12).toString("hex")}`;
}

function playFabConfigured() {
  return PLAYFAB_TITLE_ID.length > 0 && PLAYFAB_SECRET_KEY.length > 0;
}

function requirePlayFabConfigured(res) {
  if (playFabConfigured())
    return true;

  res.status(503).json({
    ok: false,
    error: "PlayFab server credentials are not configured. Set PLAYFAB_TITLE_ID and PLAYFAB_SECRET_KEY on the backend."
  });
  return false;
}

function parseNonNegativeInteger(value, fallback = 0) {
  const parsed = typeof value === "number" ? Math.floor(value) : Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed < 0)
    return fallback;
  return parsed;
}

function parseNonNegativeNumber(value, fallback = 0) {
  const parsed = typeof value === "number" ? value : Number.parseFloat(value);
  if (!Number.isFinite(parsed) || parsed < 0)
    return fallback;
  return parsed;
}

function sanitizePlayFabId(value) {
  const text = String(value ?? "").trim();
  if (!text || text.length > 64)
    return "";
  return text;
}

function sanitizeDisplayName(value) {
  const text = String(value ?? "").trim();
  return text.length > 40 ? text.slice(0, 40) : text;
}

async function playFabServerRequest(path, body) {
  const response = await fetch(`${PLAYFAB_API_BASE}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-secretkey": PLAYFAB_SECRET_KEY
    },
    body: JSON.stringify(body ?? {})
  });

  const text = await response.text();
  let parsed = null;
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = { raw: text };
    }
  }

  if (!response.ok || parsed?.code === 400 || parsed?.error) {
    const message = parsed?.errorMessage ?? parsed?.error ?? `PlayFab request failed with HTTP ${response.status}`;
    const error = new Error(message);
    error.status = response.status;
    error.playFab = parsed;
    throw error;
  }

  return parsed?.data ?? parsed ?? {};
}

async function authenticateSessionTicket(sessionTicket) {
  const ticket = String(sessionTicket ?? "").trim();
  if (!ticket) {
    const error = new Error("sessionTicket is required");
    error.status = 401;
    throw error;
  }

  let data;
  try {
    data = await playFabServerRequest("/Server/AuthenticateSessionTicket", {
      SessionTicket: ticket
    });
  } catch (error) {
    error.status = 401;
    throw error;
  }

  const playFabId = sanitizePlayFabId(data?.UserInfo?.PlayFabId ?? data?.PlayFabId);
  if (!playFabId) {
    const error = new Error("PlayFab session ticket did not resolve to a player");
    error.status = 401;
    throw error;
  }

  return playFabId;
}

function playFabServerCustomIdForItch(itchUserId) {
  const id = String(itchUserId ?? "").trim();
  if (!id) throw new Error("itchUserId is required");
  if (!ACCOUNT_LINK_HMAC_SECRET) throw new Error("ACCOUNT_LINK_HMAC_SECRET is not configured");
  return "itch_" + crypto
    .createHmac("sha256", ACCOUNT_LINK_HMAC_SECRET)
    .update(id)
    .digest("hex")
    .slice(0, 48);
}

async function loginPlayFabWithItch(itchUserId) {
  const data = await playFabServerRequest("/Server/LoginWithServerCustomId", {
    ServerCustomId: playFabServerCustomIdForItch(itchUserId),
    CreateAccount: true
  });

  const playFabId = sanitizePlayFabId(data?.PlayFabId);
  const sessionTicket = String(data?.SessionTicket ?? "").trim();
  if (!playFabId || !sessionTicket) {
    const error = new Error("PlayFab did not return a session ticket");
    error.status = 502;
    throw error;
  }

  return {
    playFabId,
    sessionTicket,
    newlyCreated: Boolean(data?.NewlyCreated)
  };
}

async function getPlayerStatistic(playFabId, statisticName) {
  const data = await playFabServerRequest("/Server/GetPlayerStatistics", {
    PlayFabId: playFabId,
    StatisticNames: [statisticName]
  });

  const stats = Array.isArray(data?.Statistics) ? data.Statistics : [];
  const match = stats.find(stat => stat?.StatisticName === statisticName);
  return parseNonNegativeInteger(match?.Value, 0);
}

async function getReadOnlyData(playFabId, keys) {
  const data = await playFabServerRequest("/Server/GetUserReadOnlyData", {
    PlayFabId: playFabId,
    Keys: keys
  });
  const values = data?.Data ?? {};
  const result = {};
  for (const key of keys)
    result[key] = String(values?.[key]?.Value ?? "").trim();
  return result;
}

async function updateReadOnlyData(playFabId, data) {
  await playFabServerRequest("/Server/UpdateUserReadOnlyData", {
    PlayFabId: playFabId,
    Data: data
  });
}

async function updatePlayerStatistic(playFabId, statisticName, value) {
  await playFabServerRequest("/Server/UpdatePlayerStatistics", {
    PlayFabId: playFabId,
    Statistics: [
      {
        StatisticName: statisticName,
        Value: parseNonNegativeInteger(value, 0)
      }
    ]
  });
}

async function addShopCrowns(playFabId, amount) {
  const delta = Math.max(0, parseNonNegativeInteger(amount, 0));
  if (delta <= 0) return;
  await playFabServerRequest("/Server/AddUserVirtualCurrency", {
    PlayFabId: playFabId,
    VirtualCurrency: SHOP_CURRENCY_CODE,
    Amount: delta
  });
}

async function subtractShopCrowns(playFabId, amount) {
  const delta = Math.max(0, parseNonNegativeInteger(amount, 0));
  if (delta <= 0) return;
  await playFabServerRequest("/Server/SubtractUserVirtualCurrency", {
    PlayFabId: playFabId,
    VirtualCurrency: SHOP_CURRENCY_CODE,
    Amount: delta
  });
}

async function grantShopItems(playFabId, itemIds) {
  const items = [...new Set((Array.isArray(itemIds) ? itemIds : []).map(id => String(id ?? "").trim()).filter(Boolean))];
  if (items.length === 0) return;
  await playFabServerRequest("/Server/GrantItemsToUser", {
    PlayFabId: playFabId,
    CatalogVersion: SHOP_CATALOG_VERSION,
    ItemIds: items
  });
}

async function getShopInventory(playFabId) {
  await refreshShopCatalog();
  const data = await playFabServerRequest("/Server/GetUserInventory", { PlayFabId: playFabId });
  const inventory = Array.isArray(data?.Inventory) ? data.Inventory : [];
  const owned = [];
  const ownedEmotes = [];
  for (const entry of inventory) {
    const itemId = String(entry?.ItemId ?? "").trim();
    const definition = SHOP_ITEMS.get(itemId);
    if (!definition) continue;
    if (definition.kind === "emote") ownedEmotes.push(itemId);
    else owned.push(itemId);
  }
  return {
    crowns: parseNonNegativeInteger(data?.VirtualCurrency?.[SHOP_CURRENCY_CODE], 0),
    owned: [...new Set(owned)],
    ownedEmotes: [...new Set(ownedEmotes)]
  };
}

async function refreshShopCatalog(force = false) {
  if (!force && Date.now() - shopCatalogLastRefresh < 60_000) return SHOP_ITEMS;
  const data = await playFabServerRequest("/Server/GetCatalogItems", { CatalogVersion: SHOP_CATALOG_VERSION });
  const entries = Array.isArray(data?.Catalog) ? data.Catalog : [];
  if (entries.length > 0) {
    SHOP_ITEMS.clear();
    for (const entry of entries) {
      const itemId = String(entry?.ItemId ?? "").trim();
      let custom = {};
      try { custom = JSON.parse(entry?.CustomData ?? "{}"); } catch { custom = {}; }
      const kind = String(custom?.kind ?? (custom?.slot ? "cosmetic" : "emote")).trim().toLowerCase();
      const slot = String(custom?.slot ?? "hat").trim().toLowerCase();
      const rawPrice = entry?.VirtualCurrencyPrices?.[SHOP_CURRENCY_CODE];
      if (!itemId) continue;
      if (kind === "emote") SHOP_ITEMS.set(itemId, { displayName: String(entry?.DisplayName ?? itemId), kind: "emote", price: parseNonNegativeInteger(rawPrice, 0) });
      else if (SHOP_SLOTS.has(slot)) SHOP_ITEMS.set(itemId, { displayName: String(entry?.DisplayName ?? itemId), kind: "cosmetic", slot, price: parseNonNegativeInteger(rawPrice, 0) });
    }
  }
  shopCatalogLastRefresh = Date.now();
  return SHOP_ITEMS;
}

async function getShopLoadout(playFabId) {
  const data = await playFabServerRequest("/Server/GetUserReadOnlyData", {
    PlayFabId: playFabId,
    Keys: ["CosmeticHat", "CosmeticShirt", "CosmeticPants", "CosmeticShoes", "CosmeticHair", "CosmeticHairColor", "CosmeticMiscellaneous", "CosmeticRevision", "EmoteWheel", "VictoryEmote", "EmoteRevision"]
  });
  const values = data?.Data ?? {};
  const value = key => String(values?.[key]?.Value ?? "").trim();
  let miscellaneous = [];
  try { miscellaneous = JSON.parse(value("CosmeticMiscellaneous") || "[]"); } catch { miscellaneous = []; }
  if (!Array.isArray(miscellaneous)) miscellaneous = [];
  let emoteWheel = [];
  try { emoteWheel = JSON.parse(value("EmoteWheel") || "[]"); } catch { emoteWheel = []; }
  return {
    hat: value("CosmeticHat"),
    shirt: value("CosmeticShirt"),
    pants: value("CosmeticPants"),
    shoes: value("CosmeticShoes"),
    hair: value("CosmeticHair"),
    hairColor: value("CosmeticHairColor"),
    miscellaneous: [...new Set(miscellaneous.map(x => String(x).trim()).filter(Boolean))].slice(0, 16),
    revision: parseNonNegativeInteger(value("CosmeticRevision"), 0),
    emoteWheel: normalizeEmoteWheel(emoteWheel),
    victoryEmote: value("VictoryEmote"),
    emoteRevision: parseNonNegativeInteger(value("EmoteRevision"), 0)
  };
}

async function saveShopLoadout(playFabId, loadout) {
  const revision = Math.max(Date.now(), parseNonNegativeInteger(loadout?.revision, 0) + 1);
  const emoteRevision = Math.max(Date.now(), parseNonNegativeInteger(loadout?.emoteRevision, 0) + 1);
  await playFabServerRequest("/Server/UpdateUserReadOnlyData", {
    PlayFabId: playFabId,
    Data: {
      CosmeticHat: String(loadout?.hat ?? ""),
      CosmeticShirt: String(loadout?.shirt ?? ""),
      CosmeticPants: String(loadout?.pants ?? ""),
      CosmeticShoes: String(loadout?.shoes ?? ""),
      CosmeticHair: String(loadout?.hair ?? ""),
      CosmeticHairColor: String(loadout?.hairColor ?? ""),
      CosmeticMiscellaneous: JSON.stringify(Array.isArray(loadout?.miscellaneous) ? loadout.miscellaneous.slice(0, 16) : []),
      CosmeticRevision: String(revision),
      EmoteWheel: JSON.stringify(normalizeEmoteWheel(loadout?.emoteWheel)),
      VictoryEmote: String(loadout?.victoryEmote ?? ""),
      EmoteRevision: String(emoteRevision)
    }
  });
  return { ...loadout, revision, emoteRevision, emoteWheel: normalizeEmoteWheel(loadout?.emoteWheel) };
}

function shopResponse(playFabId, inventory, loadout, message) {
  const receipt = mintSignedPayload({
    typ: "shop",
    pf: playFabId,
    crowns: inventory.crowns,
    owned: inventory.owned,
    hat: loadout.hat || "",
    shirt: loadout.shirt || "",
    pants: loadout.pants || "",
    shoes: loadout.shoes || "",
    hair: loadout.hair || "",
    hairColor: loadout.hairColor || "",
    miscellaneous: Array.isArray(loadout.miscellaneous) ? loadout.miscellaneous : [],
    rev: loadout.revision || 0,
    ownedEmotes: Array.isArray(inventory.ownedEmotes) ? inventory.ownedEmotes : [],
    emoteWheel: normalizeEmoteWheel(loadout.emoteWheel, inventory.ownedEmotes),
    victoryEmote: inventory.ownedEmotes?.includes(loadout.victoryEmote) ? loadout.victoryEmote : "",
    emoteRev: loadout.emoteRevision || 0
  }).token;
  return { ok: true, message, crowns: inventory.crowns, owned: inventory.owned, ownedEmotes: Array.isArray(inventory.ownedEmotes) ? inventory.ownedEmotes : [], hat: loadout.hat || "", shirt: loadout.shirt || "", pants: loadout.pants || "", shoes: loadout.shoes || "", hair: loadout.hair || "", hairColor: loadout.hairColor || "", miscellaneous: Array.isArray(loadout.miscellaneous) ? loadout.miscellaneous : [], revision: loadout.revision || 0, emoteWheel: normalizeEmoteWheel(loadout.emoteWheel, inventory.ownedEmotes), victoryEmote: inventory.ownedEmotes?.includes(loadout.victoryEmote) ? loadout.victoryEmote : "", emoteRevision: loadout.emoteRevision || 0, receipt };
}

async function getArcadeProgress(playFabId) {
  const data = await getReadOnlyData(playFabId, [ARCADE_PROGRESS_KEY]);
  try {
    return normalizeArcadeProgress(JSON.parse(data[ARCADE_PROGRESS_KEY] || "{}"));
  } catch {
    return normalizeArcadeProgress({});
  }
}

async function saveArcadeProgress(playFabId, progress) {
  const normalized = normalizeArcadeProgress(progress);
  await updateReadOnlyData(playFabId, {
    [ARCADE_PROGRESS_KEY]: JSON.stringify(normalized)
  });
  return normalized;
}

function arcadeProgressForUnity(progress) {
  const normalized = normalizeArcadeProgress(progress);
  return {
    coinBalance: normalized.coinBalance,
    bestDistance: normalized.bestDistance,
    ownedSkins: normalized.ownedSkins,
    upgradeLevels: Object.entries(normalized.upgradeLevels)
      .map(([itemId, level]) => ({ itemId, level }))
      .sort((a, b) => a.itemId.localeCompare(b.itemId)),
    selectedSkin: normalized.selectedSkin
  };
}

async function authenticatePlayFabSessionRequest(req, res) {
  const frogSession = requireFrogSession(req, res);
  if (!frogSession) return null;
  const playFabId = await authenticateSessionTicket(req.body?.sessionTicket);
  const requested = sanitizePlayFabId(req.body?.playFabId);
  if (requested && requested !== playFabId) {
    res.status(403).json({ ok: false, error: "Session ticket does not match requested PlayFabId" });
    return null;
  }
  const tokenPlayFabId = sanitizePlayFabId(frogSession?.payload?.pf);
  if (tokenPlayFabId && tokenPlayFabId !== playFabId) {
    res.status(403).json({ ok: false, error: "Frog Wars session does not match the PlayFab account" });
    return null;
  }
  return playFabId;
}

async function authenticateShopRequest(req, res) {
  return authenticatePlayFabSessionRequest(req, res);
}

function isLoadoutEmpty(loadout) {
  return !loadout ||
    !loadout.hat &&
    !loadout.shirt &&
    !loadout.pants &&
    !loadout.shoes &&
    !loadout.hair &&
    !loadout.hairColor &&
    (!Array.isArray(loadout.miscellaneous) || loadout.miscellaneous.length === 0);
}

function pruneLeaderboardReceipts() {
  const now = Date.now();
  for (const [runId, run] of arcadeRuns) {
    if (!run || now - run.startedAt > ARCADE_RUN_TTL_MS)
      arcadeRuns.delete(runId);
  }

  for (const [matchId, receipt] of processedTournamentMatches) {
    if (!receipt || now - receipt.createdAt > TOURNAMENT_MATCH_TTL_MS)
      processedTournamentMatches.delete(matchId);
  }
}

function isArcadeScorePlausible(run, score, elapsedSeconds) {
  const wallElapsed = Math.max(0, (Date.now() - run.startedAt) / 1000);
  const clientElapsed = parseNonNegativeNumber(elapsedSeconds, 0);
  const effectiveElapsed = Math.max(wallElapsed, clientElapsed);
  const maxAllowed = Math.floor(Math.max(ARCADE_DISTANCE_GRACE, effectiveElapsed * ARCADE_MAX_DISTANCE_PER_SECOND + ARCADE_DISTANCE_GRACE));
  return score <= maxAllowed && score <= ARCADE_ABSOLUTE_SCORE_CAP;
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

function directInternetDisabledResponse(res) {
  return res.status(403).json({
    error: "Direct internet rooms are disabled. Use Unity Relay for online rooms."
  });
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
    relayLobbyWaitTimeoutSeconds: RELAY_LOBBY_WAIT_TIMEOUT_SECONDS,
    playFabLeaderboardsConfigured: playFabConfigured(),
    ...itchConfigPayloadFields()
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

// itch.io ownership verification + Frog Wars session token endpoints.
// linkAccount persists the itch<->PlayFab mapping into PlayFab user data when
// both PlayFab is configured and a playFabId is supplied (best-effort, non-fatal).
registerItchOwnershipRoutes(app, {
  resolvePlayFabAccount: async (itchUserId) => {
    if (!playFabConfigured())
      return null;
    return loginPlayFabWithItch(itchUserId);
  },
  linkAccount: async (itchUserId, itchUsername, playFabId) => {
    if (!playFabConfigured() || !playFabId)
      return;
    await updateReadOnlyData(playFabId, {
      ItchUserId: String(itchUserId ?? ""),
      ItchUsername: String(itchUsername ?? ""),
      ItchLinkedAtUnixMs: String(Date.now())
    });
  }
});

app.post("/leaderboards/arcade/runs/start", async (req, res) => {
  if (!requirePlayFabConfigured(res))
    return;

  pruneLeaderboardReceipts();

  try {
    const authenticatedPlayFabId = await authenticateSessionTicket(req.body?.sessionTicket);
    const requestedPlayFabId = sanitizePlayFabId(req.body?.playFabId);
    if (requestedPlayFabId && requestedPlayFabId !== authenticatedPlayFabId)
      return res.status(403).json({ ok: false, error: "Session ticket does not match requested PlayFabId" });

    const runId = createReceiptId("arcade");
    arcadeRuns.set(runId, {
      runId,
      playFabId: authenticatedPlayFabId,
      displayName: sanitizeDisplayName(req.body?.displayName),
      startedAt: Date.now(),
      lastSubmitAt: 0,
      bestScore: 0,
      ipPrefix: maskIpPrefix(getRequesterIp(req))
    });

    return res.json({ ok: true, runId });
  } catch (error) {
    const status = error.status === 401 ? 401 : 500;
    console.warn(`[leaderboards] Arcade run start failed: ${error.message}`);
    return res.status(status).json({ ok: false, error: status === 401 ? "Invalid PlayFab session ticket" : "Backend PlayFab authentication failed" });
  }
});

app.post("/leaderboards/arcade/runs/finish", async (req, res) => {
  if (!requirePlayFabConfigured(res))
    return;

  // Ownership gate (arcade scores are owner-only by design). No-op when not enforced.
  if (!requireFrogSession(req, res))
    return;

  pruneLeaderboardReceipts();

  try {
    const authenticatedPlayFabId = await authenticateSessionTicket(req.body?.sessionTicket);
    const runId = String(req.body?.runId ?? "").trim();
    const run = arcadeRuns.get(runId);
    if (!run)
      return res.status(404).json({ ok: false, accepted: false, error: "Arcade run is missing or expired" });

    if (run.playFabId !== authenticatedPlayFabId)
      return res.status(403).json({ ok: false, accepted: false, error: "Session ticket does not match arcade run owner" });

    const now = Date.now();
    if (run.lastSubmitAt > 0 && now - run.lastSubmitAt < ARCADE_SUBMIT_MIN_INTERVAL_MS)
      return res.status(429).json({ ok: false, accepted: false, error: "Arcade score submissions are too frequent" });

    const score = parseNonNegativeInteger(req.body?.score, 0);
    if (score <= run.bestScore)
      return res.json({ ok: true, accepted: false, message: "Score was not higher than this run's accepted best" });

    if (!isArcadeScorePlausible(run, score, req.body?.elapsedSeconds)) {
      console.warn(`[leaderboards] Suspicious arcade score rejected. playFabId=${run.playFabId} score=${score} runId=${runId} ip=${run.ipPrefix ?? "unknown"}`);
      return res.status(400).json({ ok: false, accepted: false, error: "Arcade score failed timing plausibility checks" });
    }

    run.lastSubmitAt = now;
    const remoteBest = await getPlayerStatistic(run.playFabId, "HighScore");
    if (score <= remoteBest) {
      run.bestScore = Math.max(run.bestScore, score);
      return res.json({ ok: true, accepted: false, message: "Remote HighScore is already higher or equal" });
    }

    await updatePlayerStatistic(run.playFabId, "HighScore", score);
    run.bestScore = score;
    arcadeRuns.set(runId, run);
    return res.json({ ok: true, accepted: true, message: "HighScore updated" });
  } catch (error) {
    const status = error.status === 401 ? 401 : 500;
    console.warn(`[leaderboards] Arcade score submit failed: ${error.message}`);
    return res.status(status).json({ ok: false, accepted: false, error: status === 401 ? "Invalid PlayFab session ticket" : "Backend PlayFab score update failed" });
  }
});

app.post("/leaderboards/tournament/match-results", async (req, res) => {
  if (!requirePlayFabConfigured(res))
    return;

  // Ownership gate (host must be a verified owner). No-op when not enforced.
  if (!requireFrogSession(req, res))
    return;

  pruneLeaderboardReceipts();

  try {
    const authenticatedHostPlayFabId = await authenticateSessionTicket(req.body?.sessionTicket);
    const requestedHostPlayFabId = sanitizePlayFabId(req.body?.hostPlayFabId);
    if (requestedHostPlayFabId && requestedHostPlayFabId !== authenticatedHostPlayFabId)
      return res.status(403).json({ ok: false, accepted: false, error: "Session ticket does not match host PlayFabId" });

    const matchId = String(req.body?.matchId ?? "").trim();
    if (!matchId || matchId.length > 128)
      return res.status(400).json({ ok: false, accepted: false, error: "matchId is required" });

    if (processedTournamentMatches.has(matchId))
      return res.json({ ok: true, accepted: false, message: "Duplicate match receipt ignored" });

    const results = Array.isArray(req.body?.results) ? req.body.results : [];
    if (results.length === 0 || results.length > 20)
      return res.status(400).json({ ok: false, accepted: false, error: "results must contain 1 to 20 players" });

    processedTournamentMatches.set(matchId, {
      createdAt: Date.now(),
      hostPlayFabId: authenticatedHostPlayFabId,
      status: "processing"
    });

    const seenPlayers = new Set();
    const updates = [];
    for (const rawResult of results) {
      const playFabId = sanitizePlayFabId(rawResult?.playFabId);
      if (!playFabId || seenPlayers.has(playFabId))
        continue;

      seenPlayers.add(playFabId);
      const placement = parseNonNegativeInteger(rawResult?.placement, 0);
      const maxDelta = TOURNAMENT_CROWN_REWARDS.get(placement) ?? 0;
      const requestedDelta = parseNonNegativeInteger(rawResult?.crownsAwarded, 0);
      const safeDelta = Math.min(requestedDelta, maxDelta);
      if (safeDelta <= 0)
        continue;

      const requestedTotal = parseNonNegativeInteger(rawResult?.totalLifetimeCrowns, 0);
      const remoteTotal = await getPlayerStatistic(playFabId, "TournamentCrownsEarned");
      const allowedTotal = Math.max(remoteTotal, Math.min(requestedTotal, remoteTotal + safeDelta));
      if (allowedTotal <= remoteTotal)
        continue;

      const awardedDelta = allowedTotal - remoteTotal;
      await addShopCrowns(playFabId, awardedDelta);
      try {
        await updatePlayerStatistic(playFabId, "TournamentCrownsEarned", allowedTotal);
      } catch (statError) {
        console.warn(`[leaderboards] Currency awarded but lifetime statistic update failed for ${playFabId}: ${statError.message}`);
      }
      updates.push({
        playFabId,
        placement,
        value: allowedTotal,
        delta: awardedDelta
      });
    }

    processedTournamentMatches.set(matchId, {
      createdAt: Date.now(),
      hostPlayFabId: authenticatedHostPlayFabId,
      status: "accepted",
      updateCount: updates.length
    });

    return res.json({
      ok: true,
      accepted: updates.length > 0,
      message: updates.length > 0 ? `TournamentCrownsEarned updated for ${updates.length} player(s)` : "No higher tournament crown totals were accepted"
    });
  } catch (error) {
    const matchId = String(req.body?.matchId ?? "").trim();
    if (matchId && processedTournamentMatches.get(matchId)?.status === "processing")
      processedTournamentMatches.delete(matchId);

    const status = error.status === 401 ? 401 : 500;
    console.warn(`[leaderboards] Tournament result submit failed: ${error.message}`);
    return res.status(status).json({ ok: false, accepted: false, error: status === 401 ? "Invalid PlayFab session ticket" : "Backend PlayFab tournament update failed" });
  }
});

app.post("/account/migrate-legacy-playfab", async (req, res) => {
  if (!requirePlayFabConfigured(res)) return;
  try {
    const targetPlayFabId = await authenticatePlayFabSessionRequest(req, res);
    if (!targetPlayFabId) return;

    const legacyPlayFabId = await authenticateSessionTicket(req.body?.legacySessionTicket);
    if (legacyPlayFabId === targetPlayFabId)
      return res.json({ ok: true, accepted: false, message: "Legacy account already matches this account." });

    const migrationData = await getReadOnlyData(legacyPlayFabId, [
      "AccountPortabilityMigratedTo",
      "AccountPortabilityMigratedAtUnixMs"
    ]);
    const migratedTo = sanitizePlayFabId(migrationData.AccountPortabilityMigratedTo);
    if (migratedTo) {
      if (migratedTo === targetPlayFabId)
        return res.json({ ok: true, accepted: false, message: "Legacy account was already migrated." });
      return res.status(409).json({ ok: false, accepted: false, error: "Legacy account has already been migrated." });
    }

    await refreshShopCatalog();
    const [
      legacyHighScore,
      targetHighScore,
      legacyTournamentCrowns,
      targetTournamentCrowns,
      legacyInventory,
      targetInventory,
      legacyLoadout,
      targetLoadout,
      legacyArcade,
      targetArcade
    ] = await Promise.all([
      getPlayerStatistic(legacyPlayFabId, "HighScore"),
      getPlayerStatistic(targetPlayFabId, "HighScore"),
      getPlayerStatistic(legacyPlayFabId, "TournamentCrownsEarned"),
      getPlayerStatistic(targetPlayFabId, "TournamentCrownsEarned"),
      getShopInventory(legacyPlayFabId),
      getShopInventory(targetPlayFabId),
      getShopLoadout(legacyPlayFabId),
      getShopLoadout(targetPlayFabId),
      getArcadeProgress(legacyPlayFabId),
      getArcadeProgress(targetPlayFabId)
    ]);

    const updates = {};
    if (legacyHighScore > targetHighScore) {
      await updatePlayerStatistic(targetPlayFabId, "HighScore", legacyHighScore);
      updates.highScore = legacyHighScore;
    }
    if (legacyTournamentCrowns > targetTournamentCrowns) {
      await updatePlayerStatistic(targetPlayFabId, "TournamentCrownsEarned", legacyTournamentCrowns);
      updates.tournamentCrownsEarned = legacyTournamentCrowns;
    }

    const missingOwned = legacyInventory.owned.filter(itemId => !targetInventory.owned.includes(itemId));
    if (missingOwned.length > 0) {
      await grantShopItems(targetPlayFabId, missingOwned);
      updates.grantedCosmetics = missingOwned.length;
    }

    if (legacyInventory.crowns > 0) {
      await addShopCrowns(targetPlayFabId, legacyInventory.crowns);
      updates.crownsAdded = legacyInventory.crowns;
    }

    if (isLoadoutEmpty(targetLoadout) && !isLoadoutEmpty(legacyLoadout)) {
      await saveShopLoadout(targetPlayFabId, legacyLoadout);
      updates.loadoutCopied = true;
    }

    const mergedArcade = mergeArcadeProgress(targetArcade, legacyArcade);
    await saveArcadeProgress(targetPlayFabId, mergedArcade);
    updates.arcadeProgressMerged = true;

    await updateReadOnlyData(legacyPlayFabId, {
      AccountPortabilityMigratedTo: targetPlayFabId,
      AccountPortabilityMigratedAtUnixMs: String(Date.now())
    });

    return res.json({ ok: true, accepted: true, message: "Legacy account migrated.", updates });
  } catch (error) {
    const status = error.status === 401 ? 401 : 500;
    console.warn(`[account] Legacy migration failed: ${error.message}`);
    return res.status(status).json({ ok: false, accepted: false, error: status === 401 ? "Invalid PlayFab session ticket" : "Legacy account migration failed" });
  }
});

app.post("/arcade/profile", async (req, res) => {
  if (!requirePlayFabConfigured(res)) return;
  try {
    const playFabId = await authenticatePlayFabSessionRequest(req, res);
    if (!playFabId) return;
    const progress = await getArcadeProgress(playFabId);
    return res.json({ ok: true, progress: arcadeProgressForUnity(progress) });
  } catch (error) {
    const status = error.status === 401 ? 401 : 500;
    console.warn(`[arcade] Profile failed: ${error.message}`);
    return res.status(status).json({ ok: false, error: status === 401 ? "Invalid PlayFab session ticket" : "Could not load arcade progress" });
  }
});

app.post("/arcade/save", async (req, res) => {
  if (!requirePlayFabConfigured(res)) return;
  try {
    const playFabId = await authenticatePlayFabSessionRequest(req, res);
    if (!playFabId) return;
    const current = await getArcadeProgress(playFabId);
    const incoming = req.body?.progress ?? req.body;
    const merged = mergeArcadeProgress(current, incoming);
    const saved = await saveArcadeProgress(playFabId, merged);
    return res.json({ ok: true, progress: arcadeProgressForUnity(saved) });
  } catch (error) {
    const status = error.status === 401 ? 401 : 500;
    console.warn(`[arcade] Save failed: ${error.message}`);
    return res.status(status).json({ ok: false, error: status === 401 ? "Invalid PlayFab session ticket" : "Could not save arcade progress" });
  }
});

app.post("/shop/profile", async (req, res) => {
  if (!requirePlayFabConfigured(res)) return;
  try {
    const playFabId = await authenticateShopRequest(req, res);
    if (!playFabId) return;
    const [inventory, loadout] = await Promise.all([getShopInventory(playFabId), getShopLoadout(playFabId)]);
    return res.json(shopResponse(playFabId, inventory, loadout, "Wardrobe loaded."));
  } catch (error) {
    const status = error.status === 401 ? 401 : 500;
    console.warn(`[shop] Profile failed: ${error.message}`);
    return res.status(status).json({ ok: false, error: status === 401 ? "Invalid PlayFab session ticket" : "Could not load the crown shop profile" });
  }
});

app.post("/shop/purchase", async (req, res) => {
  if (!requirePlayFabConfigured(res)) return;
  try {
    const playFabId = await authenticateShopRequest(req, res);
    if (!playFabId) return;
    await refreshShopCatalog();
    const itemId = String(req.body?.itemId ?? "").trim();
    const definition = SHOP_ITEMS.get(itemId);
    if (!definition) return res.status(404).json({ ok: false, error: "That shop item is not available." });
    const before = await getShopInventory(playFabId);
    const ownedList = definition.kind === "emote" ? before.ownedEmotes : before.owned;
    const decision = purchaseDecision(before.crowns, definition.price, ownedList.includes(itemId));
    if (decision.alreadyOwned) {
      const loadout = await getShopLoadout(playFabId);
      return res.json(shopResponse(playFabId, before, loadout, `You already own this ${definition.kind === "emote" ? "emote" : "cosmetic"}.`));
    }
    if (!decision.ok) return res.status(409).json({ ok: false, error: "Not enough crowns." });

    await playFabServerRequest("/Server/PurchaseItem", {
      PlayFabId: playFabId,
      CatalogVersion: SHOP_CATALOG_VERSION,
      ItemId: itemId,
      Price: definition.price,
      VirtualCurrency: SHOP_CURRENCY_CODE
    });
    const [inventory, loadout] = await Promise.all([getShopInventory(playFabId), getShopLoadout(playFabId)]);
    return res.json(shopResponse(playFabId, inventory, loadout, `${definition.displayName} purchased.`));
  } catch (error) {
    const status = error.status === 401 ? 401 : 409;
    console.warn(`[shop] Purchase failed: ${error.message}`);
    return res.status(status).json({ ok: false, error: status === 401 ? "Invalid PlayFab session ticket" : "Purchase was declined by the crown vault." });
  }
});

app.post("/shop/equip", async (req, res) => {
  if (!requirePlayFabConfigured(res)) return;
  try {
    const playFabId = await authenticateShopRequest(req, res);
    if (!playFabId) return;
    const slot = String(req.body?.slot ?? "").trim().toLowerCase();
    const itemId = String(req.body?.itemId ?? "").trim();
    const inventory = await getShopInventory(playFabId);

    // Hair color is a FREE preference, not a purchasable item: validate the hex and store it
    // without ownership/slot checks.
    if (slot === "haircolor") {
      const loadout = await getShopLoadout(playFabId);
      loadout.hairColor = normalizeHexColor(itemId);
      const saved = await saveShopLoadout(playFabId, loadout);
      return res.json(shopResponse(playFabId, inventory, saved, loadout.hairColor ? "Hair color updated." : "Hair color reset."));
    }

    const selection = validateEquipSelection(slot, itemId, SHOP_ITEMS.get(itemId), inventory.owned);
    if (!selection.ok) return res.status(selection.error === "not-owned" ? 403 : 400).json({ ok: false, error: selection.error === "not-owned" ? "Purchase this cosmetic before equipping it." : "That item does not fit this slot." });
    const loadout = await getShopLoadout(playFabId);
    if (slot === "miscellaneous") {
      const equipped = req.body?.equipped !== false;
      loadout.miscellaneous = updateMiscellaneousSelection(loadout.miscellaneous, itemId, equipped);
    } else loadout[slot] = itemId;
    const saved = await saveShopLoadout(playFabId, loadout);
    const message = slot === "miscellaneous" && itemId && req.body?.equipped === false
      ? "Cosmetic unequipped."
      : itemId ? "Cosmetic equipped." : "Slot cleared.";
    return res.json(shopResponse(playFabId, inventory, saved, message));
  } catch (error) {
    const status = error.status === 401 ? 401 : 500;
    console.warn(`[shop] Equip failed: ${error.message}`);
    return res.status(status).json({ ok: false, error: status === 401 ? "Invalid PlayFab session ticket" : "Could not update the wardrobe." });
  }
});

app.post("/shop/emote/equip", async (req, res) => {
  if (!requirePlayFabConfigured(res)) return;
  try {
    const playFabId = await authenticateShopRequest(req, res);
    if (!playFabId) return;
    const itemId = String(req.body?.itemId ?? "").trim();
    const inventory = await getShopInventory(playFabId);
    const loadout = await getShopLoadout(playFabId);

    if (req.body?.victory === true) {
      const selection = validateVictoryEmote(itemId, inventory.ownedEmotes);
      if (!selection.ok) return res.status(403).json({ ok: false, error: "Purchase this emote before selecting it." });
      loadout.victoryEmote = selection.itemId;
      const saved = await saveShopLoadout(playFabId, loadout);
      return res.json(shopResponse(playFabId, inventory, saved, selection.itemId ? "Victory emote updated." : "Victory emote cleared."));
    }

    const update = updateEmoteWheelSlot(loadout.emoteWheel, req.body?.wheelSlot, itemId, inventory.ownedEmotes);
    if (!update.ok) return res.status(update.error === "not-owned" ? 403 : 400).json({ ok: false, error: update.error === "not-owned" ? "Purchase this emote before adding it to the wheel." : "Choose a valid emote wheel slot." });
    loadout.emoteWheel = update.wheel;
    const saved = await saveShopLoadout(playFabId, loadout);
    return res.json(shopResponse(playFabId, inventory, saved, itemId ? "Emote wheel updated." : "Emote wheel slot cleared."));
  } catch (error) {
    const status = error.status === 401 ? 401 : 500;
    console.warn(`[shop] Emote equip failed: ${error.message}`);
    return res.status(status).json({ ok: false, error: status === 401 ? "Invalid PlayFab session ticket" : "Could not update emotes." });
  }
});

app.post("/shop/spend", async (req, res) => {
  if (!requirePlayFabConfigured(res)) return;
  try {
    const playFabId = await authenticateShopRequest(req, res);
    if (!playFabId) return;
    const reason = String(req.body?.reason ?? "").trim();
    const amount = parseNonNegativeInteger(req.body?.amount, 0);
    if (reason !== "arcade-continue" || amount !== 1) return res.status(400).json({ ok: false, error: "Unsupported crown spend." });
    const before = await getShopInventory(playFabId);
    if (before.crowns < amount) return res.status(409).json({ ok: false, error: "Not enough crowns." });
    await subtractShopCrowns(playFabId, amount);
    const [inventory, loadout] = await Promise.all([getShopInventory(playFabId), getShopLoadout(playFabId)]);
    return res.json(shopResponse(playFabId, inventory, loadout, "Crown spent."));
  } catch (error) {
    const status = error.status === 401 ? 401 : 409;
    return res.status(status).json({ ok: false, error: status === 401 ? "Invalid PlayFab session ticket" : "Crown spend was declined." });
  }
});

app.post("/shop/admin/catalog", async (req, res) => {
  if (!requirePlayFabConfigured(res)) return;
  const provided = String(req.get("x-shop-admin-token") ?? "");
  if (!SHOP_ADMIN_TOKEN || provided.length !== SHOP_ADMIN_TOKEN.length || !crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(SHOP_ADMIN_TOKEN)))
    return res.status(403).json({ ok: false, error: "Invalid shop administrator token." });
  try {
    const incoming = Array.isArray(req.body?.items) ? req.body.items : [];
    const catalog = incoming.map(raw => normalizeCatalogItem(raw, SHOP_CURRENCY_CODE));
    await playFabServerRequest("/Admin/UpdateCatalogItems", { CatalogVersion: SHOP_CATALOG_VERSION, Catalog: catalog, SetAsDefaultCatalog: false });
    SHOP_ITEMS.clear();
    for (const item of catalog) {
      const custom = JSON.parse(item.CustomData);
      const kind = custom.kind === "emote" ? "emote" : "cosmetic";
      SHOP_ITEMS.set(item.ItemId, { displayName: item.DisplayName, kind, slot: custom.slot, price: item.VirtualCurrencyPrices[SHOP_CURRENCY_CODE] });
    }
    shopCatalogLastRefresh = Date.now();
    return res.json({ ok: true, message: `Published ${catalog.length} shop item(s) to PlayFab catalog ${SHOP_CATALOG_VERSION}.` });
  } catch (error) {
    console.warn(`[shop] Catalog publish failed: ${error.message}`);
    return res.status(400).json({ ok: false, error: error.message });
  }
});

app.post("/rooms", (req, res) => {
  // Ownership gate: publishing an official online room requires a verified token
  // when enforcement is active. No-op when ownership is not configured/enabled.
  if (!requireFrogSession(req, res))
    return;

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

  const publishedInternetMode = normalizeInternetMode(internetMode);
  if (publishedInternetMode === "direct" && !LEGACY_DIRECT_ENABLED)
    return directInternetDisabledResponse(res);

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
    internetMode: publishedInternetMode,
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
      relayLobbyId: null,
      relayJoinCode: null,
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

  const requestedInternetMode = typeof req.body?.internetMode === "string"
    ? normalizeInternetMode(req.body.internetMode)
    : getRoomInternetMode(room);
  if (requestedInternetMode === "direct" && !LEGACY_DIRECT_ENABLED)
    return directInternetDisabledResponse(res);

  if (typeof req.body?.currentPlayers === "number") room.currentPlayers = req.body.currentPlayers;
  if (typeof req.body?.externalAddress === "string" && req.body.externalAddress.length > 0) room.externalAddress = req.body.externalAddress;
  if (Number.isInteger(req.body?.externalPort) && req.body.externalPort > 0 && req.body.externalPort <= 65535) room.externalPort = req.body.externalPort;
  if (typeof req.body?.upnpSucceeded === "boolean") room.upnpSucceeded = req.body.upnpSucceeded;
  if (typeof req.body?.regionLabel === "string") room.regionLabel = req.body.regionLabel;
  if (typeof req.body?.transportType === "string") room.transportType = req.body.transportType;
  if (typeof req.body?.natTraversalEnabled === "boolean") room.natTraversalEnabled = req.body.natTraversalEnabled;
  if (typeof req.body?.internetMode === "string") room.internetMode = requestedInternetMode;
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
app.listen(port, () => {
  console.log(`Lobby server listening on ${port}`);
  console.log(`[startup] ${itchConfigSummaryForLog()}`);
});
