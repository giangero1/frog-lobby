export const SHOP_SLOTS = new Set(["hat", "shirt", "pants", "shoes", "hair", "miscellaneous"]);

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
  const slot = String(raw?.slot ?? "").trim().toLowerCase();
  const price = Number.isFinite(raw?.price) ? Math.floor(raw.price) : Number.parseInt(raw?.price, 10);
  if (!itemId || !SHOP_SLOTS.has(slot) || !Number.isInteger(price) || price < 0)
    throw new Error("Catalog contains an invalid item.");
  return {
    ItemId: itemId,
    DisplayName: String(raw?.displayName ?? itemId).slice(0, 80),
    VirtualCurrencyPrices: { [currencyCode]: price },
    CustomData: JSON.stringify({ slot })
  };
}
