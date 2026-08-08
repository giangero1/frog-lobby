import { purchaseDecision } from "./shopLogic.js";

const SESSION_ERROR_CODES = new Set([
  "AuthenticationContextMissing",
  "InvalidSessionTicket",
  "NotAuthenticated",
  "SessionTicketExpired"
]);

const CATALOG_ERROR_CODES = new Set([
  "CatalogNotConfigured",
  "InvalidVirtualCurrency",
  "ItemNotFound",
  "ProductDisabledForTitle",
  "StoreNotFound",
  "WrongPrice",
  "WrongVirtualCurrency"
]);

export class ShopPurchaseError extends Error {
  constructor(status, code, message, cause = null) {
    super(message, cause ? { cause } : undefined);
    this.name = "ShopPurchaseError";
    this.status = status;
    this.code = code;
    this.cause = cause ?? undefined;
  }
}

export function createKeyedSerialExecutor() {
  const tails = new Map();

  return async function runExclusive(key, action) {
    const normalizedKey = String(key ?? "").trim();
    const previous = tails.get(normalizedKey) ?? Promise.resolve();
    let release;
    const gate = new Promise(resolve => { release = resolve; });
    tails.set(normalizedKey, gate);

    await previous.catch(() => {});
    try {
      return await action();
    } finally {
      release();
      if (tails.get(normalizedKey) === gate)
        tails.delete(normalizedKey);
    }
  };
}

export function classifyPlayFabPurchaseError(error) {
  if (error instanceof ShopPurchaseError)
    return error;

  const playFabCode = String(error?.playFab?.error ?? "").trim();
  if (error?.status === 401 || error?.status === 403 || SESSION_ERROR_CODES.has(playFabCode))
    return new ShopPurchaseError(401, "invalid-session", "Your Frog Wars account session expired. Please sign in again.", error);
  if (playFabCode === "InsufficientFunds")
    return new ShopPurchaseError(409, "insufficient-crowns", "Not enough crowns.", error);
  if (CATALOG_ERROR_CODES.has(playFabCode))
    return new ShopPurchaseError(409, "item-unavailable", "That shop item is temporarily unavailable.", error);
  return new ShopPurchaseError(502, "crown-vault-unavailable", "The crown vault is temporarily unavailable. Please try again.", error);
}

export async function executeShopPurchase({
  playFabId,
  sessionTicket,
  itemId,
  definition,
  currencyCode,
  catalogVersion,
  getInventory,
  getLoadout,
  purchaseItem,
  buildResponse
}) {
  if (!definition)
    throw new ShopPurchaseError(404, "item-unavailable", "That shop item is not available.");

  const before = await getInventory(playFabId);
  const ownedList = definition.kind === "emote" ? before.ownedEmotes : before.owned;
  const decision = purchaseDecision(before.crowns, definition.price, ownedList.includes(itemId));
  if (decision.alreadyOwned) {
    const loadout = await getLoadout(playFabId);
    return buildResponse(
      playFabId,
      before,
      loadout,
      `You already own this ${definition.kind === "emote" ? "emote" : "cosmetic"}.`);
  }
  if (!decision.ok)
    throw new ShopPurchaseError(409, "insufficient-crowns", "Not enough crowns.");

  try {
    await purchaseItem(sessionTicket, {
      CatalogVersion: catalogVersion,
      ItemId: itemId,
      Price: definition.price,
      VirtualCurrency: currencyCode
    });
  } catch (error) {
    throw classifyPlayFabPurchaseError(error);
  }

  const [inventory, loadout] = await Promise.all([getInventory(playFabId), getLoadout(playFabId)]);
  return buildResponse(playFabId, inventory, loadout, `${definition.displayName} purchased.`);
}
