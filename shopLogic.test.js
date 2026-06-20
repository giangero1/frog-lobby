import test from "node:test";
import assert from "node:assert/strict";
import { normalizeCatalogItem, purchaseDecision, validateEquipSelection } from "./shopLogic.js";

test("purchase rejects insufficient balance and accepts owned idempotently", () => {
  assert.equal(purchaseDecision(4, 5, false).error, "insufficient-crowns");
  assert.deepEqual(purchaseDecision(0, 20, true), { ok: true, alreadyOwned: true });
});

test("equip requires ownership and the matching slot", () => {
  const definition = { slot: "hat" };
  assert.equal(validateEquipSelection("shoes", "king-crown", definition, ["king-crown"]).error, "wrong-slot");
  assert.equal(validateEquipSelection("hat", "king-crown", definition, []).error, "not-owned");
  assert.equal(validateEquipSelection("hat", "king-crown", definition, ["king-crown"]).ok, true);
  assert.equal(validateEquipSelection("hat", "", null, []).ok, true);
});

test("catalog publishing normalizes safe PlayFab entries", () => {
  assert.deepEqual(normalizeCatalogItem({ itemId: "king-crown", displayName: "King Crown", slot: "HAT", price: 20 }, "CR"), {
    ItemId: "king-crown",
    DisplayName: "King Crown",
    VirtualCurrencyPrices: { CR: 20 },
    CustomData: "{\"slot\":\"hat\"}"
  });
  assert.throws(() => normalizeCatalogItem({ itemId: "bad", slot: "weapon", price: 1 }, "CR"));
});
