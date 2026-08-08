import test from "node:test";
import assert from "node:assert/strict";
import { classifyPlayFabPurchaseError, createKeyedSerialExecutor, executeShopPurchase, ShopPurchaseError } from "./shopPurchase.js";

const definition = { displayName: "Shtreimel", kind: "cosmetic", slot: "hat", price: 8 };
const loadout = { hat: "", shirt: "", pants: "", shoes: "", hair: "", hairColor: "", miscellaneous: [] };
const buildResponse = (_playFabId, inventory, _loadout, message) => ({ ok: true, message, ...inventory });

function inventoryState(crowns = 17, owned = []) {
  const state = { crowns, owned: [...owned], ownedEmotes: [] };
  return {
    state,
    getInventory: async () => ({ crowns: state.crowns, owned: [...state.owned], ownedEmotes: [...state.ownedEmotes] })
  };
}

function execute(overrides = {}) {
  return executeShopPurchase({
    playFabId: "P1",
    sessionTicket: "ticket",
    itemId: "shtreimel",
    definition,
    currencyCode: "CR",
    catalogVersion: "Cosmetics",
    getInventory: async () => ({ crowns: 17, owned: [], ownedEmotes: [] }),
    getLoadout: async () => loadout,
    purchaseItem: async () => {},
    buildResponse,
    ...overrides
  });
}

test("successful purchase charges the live price and returns refreshed balance and ownership", async () => {
  const { state, getInventory } = inventoryState();
  let purchaseBody;
  const response = await execute({
    getInventory,
    purchaseItem: async (_ticket, body) => {
      purchaseBody = body;
      state.crowns -= body.Price;
      state.owned.push(body.ItemId);
    }
  });
  assert.deepEqual(purchaseBody, { CatalogVersion: "Cosmetics", ItemId: "shtreimel", Price: 8, VirtualCurrency: "CR" });
  assert.equal(response.crowns, 9);
  assert.deepEqual(response.owned, ["shtreimel"]);
});

test("insufficient balance is rejected before PlayFab purchase", async () => {
  let purchaseCalls = 0;
  await assert.rejects(
    execute({
      getInventory: async () => ({ crowns: 7, owned: [], ownedEmotes: [] }),
      purchaseItem: async () => { purchaseCalls++; }
    }),
    error => error instanceof ShopPurchaseError && error.code === "insufficient-crowns"
  );
  assert.equal(purchaseCalls, 0);
});

test("already-owned purchase is idempotent and does not charge again", async () => {
  let purchaseCalls = 0;
  const response = await execute({
    getInventory: async () => ({ crowns: 9, owned: ["shtreimel"], ownedEmotes: [] }),
    purchaseItem: async () => { purchaseCalls++; }
  });
  assert.equal(purchaseCalls, 0);
  assert.equal(response.crowns, 9);
  assert.match(response.message, /already own/i);
});

test("missing definitions are reported as unavailable", async () => {
  await assert.rejects(execute({ definition: null }), error => error.status === 404 && error.code === "item-unavailable");
});

test("PlayFab purchase failures map to stable safe errors", () => {
  const cases = [
    ["InsufficientFunds", "insufficient-crowns", 409],
    ["WrongPrice", "item-unavailable", 409],
    ["ItemNotFound", "item-unavailable", 409],
    ["InvalidSessionTicket", "invalid-session", 401],
    ["ServiceUnavailable", "crown-vault-unavailable", 502]
  ];
  for (const [playFabCode, expectedCode, expectedStatus] of cases) {
    const source = Object.assign(new Error(playFabCode), { status: 400, playFab: { error: playFabCode } });
    const result = classifyPlayFabPurchaseError(source);
    assert.equal(result.code, expectedCode, playFabCode);
    assert.equal(result.status, expectedStatus, playFabCode);
  }
});

test("same-account concurrent requests serialize and purchase a durable item once", async () => {
  const runExclusive = createKeyedSerialExecutor();
  const { state, getInventory } = inventoryState();
  let purchaseCalls = 0;
  const action = () => runExclusive("P1", () => execute({
    getInventory,
    purchaseItem: async (_ticket, body) => {
      purchaseCalls++;
      await new Promise(resolve => setTimeout(resolve, 10));
      state.crowns -= body.Price;
      state.owned.push(body.ItemId);
    }
  }));

  const [first, second] = await Promise.all([action(), action()]);
  assert.equal(purchaseCalls, 1);
  assert.equal(state.crowns, 9);
  assert.deepEqual(state.owned, ["shtreimel"]);
  assert.equal(first.crowns, 9);
  assert.equal(second.crowns, 9);
});
