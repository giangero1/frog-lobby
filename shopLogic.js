export const SHOP_SLOTS = new Set(["hat", "shirt", "pants", "shoes"]);

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
