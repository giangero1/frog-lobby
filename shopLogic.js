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

const COSMETIC_DATA_KEYS = Object.freeze({
  hat: "CosmeticHat",
  shirt: "CosmeticShirt",
  pants: "CosmeticPants",
  shoes: "CosmeticShoes",
  hair: "CosmeticHair",
  haircolor: "CosmeticHairColor"
});

function appendOptionalString(update, key, value) {
  const normalized = String(value ?? "").trim();
  if (normalized) update.Data[key] = normalized;
  else update.KeysToRemove.push(key);
}

function finalizePlayerDataUpdate(update) {
  if (update.KeysToRemove.length === 0) delete update.KeysToRemove;
  return update;
}

export function buildCosmeticLoadoutUpdate(loadout, slot, revision) {
  const normalizedSlot = String(slot ?? "").trim().toLowerCase();
  const update = { Data: { CosmeticRevision: String(revision) }, KeysToRemove: [] };
  if (normalizedSlot === "miscellaneous") {
    update.Data.CosmeticMiscellaneous = JSON.stringify(
      Array.isArray(loadout?.miscellaneous) ? loadout.miscellaneous.slice(0, 16) : []
    );
  } else {
    const key = COSMETIC_DATA_KEYS[normalizedSlot];
    if (!key) throw new Error(`Unsupported cosmetic loadout slot: ${normalizedSlot || "<empty>"}`);
    const property = normalizedSlot === "haircolor" ? "hairColor" : normalizedSlot;
    appendOptionalString(update, key, loadout?.[property]);
  }
  return finalizePlayerDataUpdate(update);
}

export function buildEmoteLoadoutUpdate(loadout, field, revision) {
  const normalizedField = String(field ?? "").trim().toLowerCase();
  const update = { Data: { EmoteRevision: String(revision) }, KeysToRemove: [] };
  if (normalizedField === "wheel")
    update.Data.EmoteWheel = JSON.stringify(normalizeEmoteWheel(loadout?.emoteWheel));
  else if (normalizedField === "victory")
    appendOptionalString(update, "VictoryEmote", loadout?.victoryEmote);
  else
    throw new Error(`Unsupported emote loadout field: ${normalizedField || "<empty>"}`);
  return finalizePlayerDataUpdate(update);
}

export function buildFullLoadoutUpdate(loadout, revision, emoteRevision) {
  const update = {
    Data: {
      CosmeticMiscellaneous: JSON.stringify(Array.isArray(loadout?.miscellaneous) ? loadout.miscellaneous.slice(0, 16) : []),
      CosmeticRevision: String(revision),
      EmoteWheel: JSON.stringify(normalizeEmoteWheel(loadout?.emoteWheel)),
      EmoteRevision: String(emoteRevision)
    },
    KeysToRemove: []
  };
  for (const [slot, key] of Object.entries(COSMETIC_DATA_KEYS)) {
    const property = slot === "haircolor" ? "hairColor" : slot;
    appendOptionalString(update, key, loadout?.[property]);
  }
  appendOptionalString(update, "VictoryEmote", loadout?.victoryEmote);
  return finalizePlayerDataUpdate(update);
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

export function normalizeCatalogItems(rawItems, currencyCode) {
  const seen = new Set();
  return (Array.isArray(rawItems) ? rawItems : []).map(raw => {
    const item = normalizeCatalogItem(raw, currencyCode);
    if (seen.has(item.ItemId))
      throw new Error(`Catalog contains duplicate item id '${item.ItemId}'.`);
    seen.add(item.ItemId);
    return item;
  });
}

export function normalizePublishedCatalog(entries, currencyCode) {
  const seen = new Set();
  return (Array.isArray(entries) ? entries : []).map(entry => {
    const itemId = String(entry?.ItemId ?? "").trim();
    if (!itemId)
      throw new Error("Published catalog contains an item without an id.");
    if (seen.has(itemId))
      throw new Error(`Published catalog contains duplicate item id '${itemId}'.`);
    seen.add(itemId);

    let custom;
    try {
      custom = JSON.parse(entry?.CustomData ?? "{}");
    } catch {
      throw new Error(`Published catalog item '${itemId}' has invalid custom data.`);
    }

    const kind = String(custom?.kind ?? (custom?.slot ? "cosmetic" : "emote")).trim().toLowerCase();
    const slot = String(custom?.slot ?? "").trim().toLowerCase();
    const rawPrice = entry?.VirtualCurrencyPrices?.[currencyCode];
    const price = Number.isInteger(rawPrice) ? rawPrice : Number.parseInt(rawPrice, 10);
    if (!SHOP_KINDS.has(kind) || !Number.isInteger(price) || price < 0)
      throw new Error(`Published catalog item '${itemId}' has an invalid kind or ${currencyCode} price.`);
    if (kind === "cosmetic" && !SHOP_SLOTS.has(slot))
      throw new Error(`Published catalog item '${itemId}' has invalid slot '${slot}'.`);

    return {
      itemId,
      displayName: String(entry?.DisplayName ?? itemId),
      kind,
      slot: kind === "cosmetic" ? slot : undefined,
      price
    };
  });
}

export function catalogPublishMismatches(expectedCatalog, actualDefinitions, requireExact = false, currencyCode = "CR") {
  const actualById = new Map((Array.isArray(actualDefinitions) ? actualDefinitions : []).map(item => [item.itemId, item]));
  const mismatches = [];
  for (const expected of Array.isArray(expectedCatalog) ? expectedCatalog : []) {
    const itemId = expected.ItemId;
    const actual = actualById.get(itemId);
    let custom = {};
    try { custom = JSON.parse(expected.CustomData ?? "{}"); } catch { custom = {}; }
    const expectedKind = custom.kind === "emote" ? "emote" : "cosmetic";
    const expectedSlot = expectedKind === "cosmetic" ? String(custom.slot ?? "") : undefined;
    const expectedPrice = expected.VirtualCurrencyPrices?.[currencyCode];
    if (!actual) {
      mismatches.push(`${itemId}: missing`);
      continue;
    }
    if (actual.kind !== expectedKind || actual.slot !== expectedSlot || actual.price !== expectedPrice)
      mismatches.push(`${itemId}: expected ${expectedKind}/${expectedSlot ?? "-"}/${expectedPrice}, got ${actual.kind}/${actual.slot ?? "-"}/${actual.price}`);
  }
  if (requireExact && actualById.size !== (Array.isArray(expectedCatalog) ? expectedCatalog.length : 0))
    mismatches.push(`catalog count: expected ${expectedCatalog.length}, got ${actualById.size}`);
  return mismatches;
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
