const DAY_MS = 24 * 60 * 60 * 1000;

export const DEFAULT_FISHING_CONFIG = Object.freeze({
  intervalMs: 90_000,
  crownChanceBasisPoints: 400,
  pityRolls: 40,
  dailyCap: 8
});

export function utcDayKey(nowMs = Date.now()) {
  return new Date(nowMs).toISOString().slice(0, 10);
}

export function normalizeFishingConfig(raw = {}) {
  return {
    intervalMs: clampInt(raw.intervalMs, 5_000, DAY_MS, DEFAULT_FISHING_CONFIG.intervalMs),
    crownChanceBasisPoints: clampInt(raw.crownChanceBasisPoints, 0, 10_000, DEFAULT_FISHING_CONFIG.crownChanceBasisPoints),
    pityRolls: clampInt(raw.pityRolls, 1, 10_000, DEFAULT_FISHING_CONFIG.pityRolls),
    dailyCap: clampInt(raw.dailyCap, 0, 10_000, DEFAULT_FISHING_CONFIG.dailyCap)
  };
}

export function normalizeFishingState(raw, nowMs = Date.now()) {
  const source = raw && typeof raw === "object" ? raw : {};
  const day = utcDayKey(nowMs);
  const sameDay = String(source.day ?? "") === day;
  return {
    day,
    awardedToday: sameDay ? clampInt(source.awardedToday, 0, 10_000, 0) : 0,
    dryRolls: sameDay ? clampInt(source.dryRolls, 0, 1_000_000, 0) : 0,
    active: Boolean(source.active),
    roomId: sanitizeId(source.roomId, 128),
    nextEligibleAt: clampInt(source.nextEligibleAt, 0, Number.MAX_SAFE_INTEGER, 0),
    lastRequestId: sanitizeId(source.lastRequestId, 128),
    lastResult: source.lastResult && typeof source.lastResult === "object" ? source.lastResult : null
  };
}

export function startFishing(rawState, roomId, nowMs, config = DEFAULT_FISHING_CONFIG) {
  const settings = normalizeFishingConfig(config);
  const state = normalizeFishingState(rawState, nowMs);
  state.active = true;
  state.roomId = sanitizeId(roomId, 128);
  state.nextEligibleAt = Math.max(state.nextEligibleAt, nowMs + settings.intervalMs);
  state.lastRequestId = "";
  state.lastResult = null;
  return state;
}

export function stopFishing(rawState, nowMs = Date.now()) {
  const state = normalizeFishingState(rawState, nowMs);
  state.active = false;
  state.roomId = "";
  state.nextEligibleAt = 0;
  state.lastRequestId = "";
  state.lastResult = null;
  return state;
}

export function resolveFishingRoll(rawState, options = {}) {
  const nowMs = Number.isFinite(options.nowMs) ? Math.floor(options.nowMs) : Date.now();
  const requestId = sanitizeId(options.requestId, 128);
  const roomId = sanitizeId(options.roomId, 128);
  const settings = normalizeFishingConfig(options.config);
  const state = normalizeFishingState(rawState, nowMs);

  if (!requestId) return { ok: false, error: "invalid-request-id", state };
  if (state.lastRequestId === requestId && state.lastResult)
    return { ok: true, duplicate: true, state, result: state.lastResult };
  if (!state.active || !state.roomId || state.roomId !== roomId)
    return { ok: false, error: "not-active", state };
  if (nowMs < state.nextEligibleAt)
    return { ok: false, error: "too-early", retryAfterMs: state.nextEligibleAt - nowMs, state };

  const atCap = state.awardedToday >= settings.dailyCap;
  const nextDryRolls = state.dryRolls + 1;
  const randomBasisPoints = clampInt(options.randomBasisPoints, 0, 9_999, 9_999);
  const chanceHit = randomBasisPoints < settings.crownChanceBasisPoints;
  const pityHit = nextDryRolls >= settings.pityRolls;
  const crownAwarded = !atCap && (chanceHit || pityHit) ? 1 : 0;

  state.awardedToday = Math.min(settings.dailyCap, state.awardedToday + crownAwarded);
  state.dryRolls = crownAwarded > 0 ? 0 : nextDryRolls;
  state.nextEligibleAt = nowMs + settings.intervalMs;
  const result = {
    crownAwarded,
    awardedToday: state.awardedToday,
    dailyCap: settings.dailyCap,
    capped: state.awardedToday >= settings.dailyCap,
    pity: crownAwarded > 0 && pityHit && !chanceHit,
    nextEligibleAt: state.nextEligibleAt
  };
  state.lastRequestId = requestId;
  state.lastResult = result;
  return { ok: true, duplicate: false, state, result };
}

function sanitizeId(value, maxLength) {
  const text = String(value ?? "").trim();
  if (!text || text.length > maxLength || !/^[a-zA-Z0-9_.:-]+$/.test(text)) return "";
  return text;
}

function clampInt(value, min, max, fallback) {
  const parsed = Number.isFinite(value) ? Math.floor(value) : Number.parseInt(value, 10);
  if (!Number.isInteger(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}
