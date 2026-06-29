export const SHOP_SLOTS = new Set(["hat", "shirt", "pants", "shoes", "hair", "miscellaneous"]);
export const SHOP_KINDS = new Set(["cosmetic", "emote"]);
export const ARCADE_PURCHASE_REWARD_CROWNS = 2;
export const ARCADE_REWARD_SKIN_IDS = new Set(["americafirsthat", "shtreimel", "crusader-helmet", "crown"]);
export const ARCADE_REWARD_UPGRADE_MAX_LEVELS = new Map([
  ["thruster", 5],
  ["jetpack", 5],
  ["engine", 5],
  ["fueltank", 5]
]);

export function purchaseDecision(balance, price, alreadyOwned) {
  if (alreadyOwned) return { ok: true, alreadyOwned: true };
  if (!Number.isInteger(price) || price < 0) return { ok: false, error: "invalid-price" };
  if (!Number.isFinite(balance) || balance < price) return { ok: false, error: "insufficient-crowns" };
  return { ok: true, alreadyOwned: false };
}

export function validateEquipSelection(slot, itemId, definition, owned) {
  if (!SHOP_SLOTS.has(slot)) return { ok: false, error: "unknown-slot" };
  if (!itemId) return { ok: true };
  if (!definition || definition.slot !== slot) return { ok: false, error: "wrong-slot" };
  if (!owned.includes(itemId)) return { ok: false, error: "not-owned" };
  return { ok: true };
}

export function updateMiscellaneousSelection(current, itemId, equipped, limit = 16) {
  const items = new Set(Array.isArray(current) ? current.map(x => String(x).trim()).filter(Boolean) : []);
  if (!itemId) items.clear();
  else if (equipped) items.add(itemId);
  else items.delete(itemId);
  return [...items].slice(0, limit);
}

export function normalizeEmoteWheel(current, owned = null, limit = 8) {
  const ownedSet = Array.isArray(owned) ? new Set(owned.map(x => String(x).trim()).filter(Boolean)) : null;
  const source = Array.isArray(current) ? current : [];
  const wheel = [];
  for (let i = 0; i < limit; i++) {
    const itemId = String(source[i] ?? "").trim();
    wheel.push(itemId && (!ownedSet || ownedSet.has(itemId)) ? itemId : "");
  }
  return wheel;
}

export function updateEmoteWheelSlot(current, slot, itemId, owned, limit = 8) {
  const index = Number.isInteger(slot) ? slot : Number.parseInt(slot, 10);
  if (!Number.isInteger(index) || index < 0 || index >= limit) return { ok: false, error: "invalid-wheel-slot" };
  const normalizedId = String(itemId ?? "").trim();
  if (normalizedId && (!Array.isArray(owned) || !owned.includes(normalizedId))) return { ok: false, error: "not-owned" };
  const wheel = normalizeEmoteWheel(current, owned, limit);
  wheel[index] = normalizedId;
  return { ok: true, wheel };
}

export function validateVictoryEmote(itemId, owned) {
  const normalizedId = String(itemId ?? "").trim();
  if (!normalizedId) return { ok: true, itemId: "" };
  if (!Array.isArray(owned) || !owned.includes(normalizedId)) return { ok: false, error: "not-owned" };
  return { ok: true, itemId: normalizedId };
}

/**
 * Normalizes a hair-color hex string to canonical 8-digit "RRGGBBAA" upper-case, or "" when
 * empty/invalid. Accepts optional leading '#', and 6- or 8-digit hex (6 implies opaque alpha).
 */
export function normalizeHexColor(value) {
  let hex = String(value ?? "").trim().replace(/^#/, "");
  if (hex.length === 0) return "";
  if (!/^[0-9a-fA-F]+$/.test(hex)) return "";
  if (hex.length === 6) hex += "FF";
  if (hex.length !== 8) return "";
  return hex.toUpperCase();
}

export function normalizeCatalogItem(raw, currencyCode) {
  const itemId = String(raw?.itemId ?? "").trim();
  const explicitKind = String(raw?.kind ?? raw?.type ?? "").trim().toLowerCase();
  const slot = String(raw?.slot ?? "").trim().toLowerCase();
  const kind = explicitKind || (slot ? "cosmetic" : "emote");
  const price = Number.isFinite(raw?.price) ? Math.floor(raw.price) : Number.parseInt(raw?.price, 10);
  if (!itemId || !SHOP_KINDS.has(kind) || !Number.isInteger(price) || price < 0)
    throw new Error("Catalog contains an invalid item.");
  if (kind === "cosmetic" && !SHOP_SLOTS.has(slot))
    throw new Error("Catalog contains an invalid item.");
  return {
    ItemId: itemId,
    DisplayName: String(raw?.displayName ?? itemId).slice(0, 80),
    VirtualCurrencyPrices: { [currencyCode]: price },
    CustomData: JSON.stringify(kind === "emote" ? { kind: "emote" } : { kind: "cosmetic", slot })
  };
}

export function normalizeArcadeProgress(raw, allowedItemIds = null) {
  const allowed = allowedItemIds instanceof Set ? allowedItemIds : null;
  const coinBalance = clampInt(raw?.coinBalance, 0, 999999999);
  const bestDistance = clampInt(raw?.bestDistance, 0, 1000000000);
  const selectedSkin = normalizeArcadeItemId(raw?.selectedSkin, allowed);
  const ownedSkins = normalizeArcadeItemList(raw?.ownedSkins, allowed);
  const upgradeLevels = {};
  const inputUpgrades = raw?.upgradeLevels;
  if (Array.isArray(inputUpgrades)) {
    for (const entry of inputUpgrades) {
      const itemId = normalizeArcadeItemId(entry?.itemId, allowed);
      if (!itemId) continue;
      upgradeLevels[itemId] = clampInt(entry?.level, 0, 100);
    }
  } else if (inputUpgrades && typeof inputUpgrades === "object") {
    for (const [key, value] of Object.entries(inputUpgrades)) {
      const itemId = normalizeArcadeItemId(key, allowed);
      if (!itemId) continue;
      upgradeLevels[itemId] = clampInt(value, 0, 100);
    }
  }

  return {
    coinBalance,
    bestDistance,
    ownedSkins,
    upgradeLevels,
    selectedSkin: selectedSkin && ownedSkins.includes(selectedSkin) ? selectedSkin : ""
  };
}

export function mergeArcadeProgress(existing, incoming, allowedItemIds = null) {
  const current = normalizeArcadeProgress(existing, allowedItemIds);
  const next = normalizeArcadeProgress(incoming, allowedItemIds);
  const owned = new Set([...current.ownedSkins, ...next.ownedSkins]);
  const upgradeLevels = { ...current.upgradeLevels };
  for (const [itemId, level] of Object.entries(next.upgradeLevels))
    upgradeLevels[itemId] = Math.max(upgradeLevels[itemId] ?? 0, level);

  const selectedSkin = next.selectedSkin && owned.has(next.selectedSkin)
    ? next.selectedSkin
    : current.selectedSkin && owned.has(current.selectedSkin)
      ? current.selectedSkin
      : "";

  return {
    coinBalance: Math.max(current.coinBalance, next.coinBalance),
    bestDistance: Math.max(current.bestDistance, next.bestDistance),
    ownedSkins: [...owned].sort(),
    upgradeLevels,
    selectedSkin
  };
}

export function normalizeArcadeRewardState(raw) {
  const rewardedSkins = normalizeArcadeItemList(raw?.rewardedSkins ?? raw?.skins, ARCADE_REWARD_SKIN_IDS);
  const rewardedUpgradeLevels = {};
  const source = raw?.rewardedUpgradeLevels ?? raw?.upgradeLevels;
  if (source && typeof source === "object") {
    for (const [key, value] of Object.entries(source)) {
      const itemId = normalizeArcadeItemId(key, new Set(ARCADE_REWARD_UPGRADE_MAX_LEVELS.keys()));
      if (!itemId) continue;
      const maxLevel = ARCADE_REWARD_UPGRADE_MAX_LEVELS.get(itemId) ?? 0;
      const level = clampInt(value, 0, maxLevel);
      if (level > 0) rewardedUpgradeLevels[itemId] = level;
    }
  }

  return {
    rewardedSkins,
    rewardedUpgradeLevels
  };
}

export function arcadePurchaseRewardDecision(currentState, rawRequest) {
  const state = normalizeArcadeRewardState(currentState);
  const itemId = normalizeArcadeItemId(rawRequest?.itemId, null);
  const itemType = String(rawRequest?.itemType ?? rawRequest?.type ?? "").trim().toLowerCase();

  if (itemType === "skin") {
    if (!ARCADE_REWARD_SKIN_IDS.has(itemId)) return { ok: false, error: "unknown-arcade-item" };
    if (state.rewardedSkins.includes(itemId))
      return { ok: true, alreadyRewarded: true, crownsAwarded: 0, state };

    state.rewardedSkins = [...state.rewardedSkins, itemId].sort();
    return { ok: true, alreadyRewarded: false, crownsAwarded: ARCADE_PURCHASE_REWARD_CROWNS, state };
  }

  if (itemType === "upgrade") {
    if (!ARCADE_REWARD_UPGRADE_MAX_LEVELS.has(itemId)) return { ok: false, error: "unknown-arcade-item" };
    const maxLevel = ARCADE_REWARD_UPGRADE_MAX_LEVELS.get(itemId);
    const level = clampInt(rawRequest?.level, -1, maxLevel);
    const previousLevel = state.rewardedUpgradeLevels[itemId] ?? 0;
    if (level >= 1 && level <= previousLevel)
      return { ok: true, alreadyRewarded: true, crownsAwarded: 0, state };
    if (level < 1 || level > maxLevel || level !== previousLevel + 1)
      return { ok: false, error: "invalid-upgrade-level" };

    state.rewardedUpgradeLevels[itemId] = level;
    return { ok: true, alreadyRewarded: false, crownsAwarded: ARCADE_PURCHASE_REWARD_CROWNS, state };
  }

  return { ok: false, error: "unknown-arcade-item-type" };
}

function normalizeArcadeItemList(value, allowed) {
  const source = Array.isArray(value) ? value : [];
  const items = new Set();
  for (const raw of source) {
    const itemId = normalizeArcadeItemId(raw, allowed);
    if (itemId) items.add(itemId);
  }
  return [...items].sort();
}

function normalizeArcadeItemId(value, allowed) {
  const itemId = String(value ?? "").trim();
  if (!itemId || itemId.length > 80 || !/^[a-z0-9][a-z0-9_.-]*$/i.test(itemId)) return "";
  if (allowed && !allowed.has(itemId)) return "";
  return itemId;
}

function clampInt(value, min, max) {
  const parsed = Number.isFinite(value) ? Math.floor(value) : Number.parseInt(value, 10);
  if (!Number.isInteger(parsed)) return min;
  return Math.min(max, Math.max(min, parsed));
}
