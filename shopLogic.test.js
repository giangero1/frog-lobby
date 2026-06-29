import test from "node:test";
import assert from "node:assert/strict";
import { mergeArcadeProgress, normalizeArcadeProgress, normalizeCatalogItem, normalizeEmoteWheel, normalizeHexColor, purchaseDecision, updateEmoteWheelSlot, updateMiscellaneousSelection, validateEquipSelection, validateVictoryEmote } from "./shopLogic.js";

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
  assert.equal(validateEquipSelection("miscellaneous", "charlie-chaplin-mustache", { slot: "miscellaneous" }, ["charlie-chaplin-mustache"]).ok, true);
});

test("catalog accepts stackable miscellaneous cosmetics", () => {
  const item = normalizeCatalogItem({ itemId: "charlie-chaplin-mustache", displayName: "Charlie Chaplin Mustache", slot: "miscellaneous", price: 16 }, "CR");
  assert.equal(item.CustomData, '{"kind":"cosmetic","slot":"miscellaneous"}');
  assert.equal(item.VirtualCurrencyPrices.CR, 16);
});

test("catalog accepts emote entries with emote custom data", () => {
  const item = normalizeCatalogItem({ itemId: "wave", displayName: "Wave", kind: "emote", price: 0 }, "CR");
  assert.equal(item.CustomData, '{"kind":"emote"}');
  assert.equal(item.VirtualCurrencyPrices.CR, 0);
});

test("miscellaneous cosmetics equip independently and can all be cleared", () => {
  assert.deepEqual(updateMiscellaneousSelection(["glasses"], "charlie-chaplin-mustache", true), ["glasses", "charlie-chaplin-mustache"]);
  assert.deepEqual(updateMiscellaneousSelection(["glasses", "charlie-chaplin-mustache"], "glasses", false), ["charlie-chaplin-mustache"]);
  assert.deepEqual(updateMiscellaneousSelection(["charlie-chaplin-mustache"], "", false), []);
});

test("catalog publishing normalizes safe PlayFab entries", () => {
  assert.deepEqual(normalizeCatalogItem({ itemId: "king-crown", displayName: "King Crown", slot: "HAT", price: 20 }, "CR"), {
    ItemId: "king-crown",
    DisplayName: "King Crown",
    VirtualCurrencyPrices: { CR: 20 },
    CustomData: "{\"kind\":\"cosmetic\",\"slot\":\"hat\"}"
  });
  assert.throws(() => normalizeCatalogItem({ itemId: "bad", slot: "weapon", price: 1 }, "CR"));
});

test("emote wheel normalization and slot updates require owned emotes", () => {
  assert.deepEqual(normalizeEmoteWheel(["wave", "bad"], ["wave"]), ["wave", "", "", "", "", "", "", ""]);
  assert.equal(updateEmoteWheelSlot([], 8, "wave", ["wave"]).error, "invalid-wheel-slot");
  assert.equal(updateEmoteWheelSlot([], 0, "wave", []).error, "not-owned");
  assert.deepEqual(updateEmoteWheelSlot([], 0, "wave", ["wave"]).wheel, ["wave", "", "", "", "", "", "", ""]);
});

test("victory emote validation requires ownership but allows clearing", () => {
  assert.deepEqual(validateVictoryEmote("", []), { ok: true, itemId: "" });
  assert.equal(validateVictoryEmote("dance", ["wave"]).error, "not-owned");
  assert.deepEqual(validateVictoryEmote("dance", ["dance"]), { ok: true, itemId: "dance" });
});

test("hair color normalizes to canonical RRGGBBAA or empty", () => {
  assert.equal(normalizeHexColor("#ff8800"), "FF8800FF");
  assert.equal(normalizeHexColor("aabbccdd"), "AABBCCDD");
  assert.equal(normalizeHexColor(""), "");
  assert.equal(normalizeHexColor("xyz"), "");
  assert.equal(normalizeHexColor("12345"), "");
});

test("arcade progress normalizes and clamps unsafe save data", () => {
  assert.deepEqual(normalizeArcadeProgress({
    coinBalance: -10,
    bestDistance: "42",
    ownedSkins: ["plane-red", "../bad", "plane-red"],
    selectedSkin: "../bad",
    upgradeLevels: { "engine": "3", "../bad": 99, "boost": 101 }
  }), {
    coinBalance: 0,
    bestDistance: 42,
    ownedSkins: ["plane-red"],
    selectedSkin: "",
    upgradeLevels: { engine: 3, boost: 100 }
  });
});

test("arcade progress merge keeps highest values and union ownership", () => {
  assert.deepEqual(mergeArcadeProgress(
    { coinBalance: 5, bestDistance: 100, ownedSkins: ["green"], selectedSkin: "green", upgradeLevels: { engine: 1 } },
    { coinBalance: 3, bestDistance: 120, ownedSkins: ["red"], selectedSkin: "red", upgradeLevels: { engine: 2, fuel: 1 } }
  ), {
    coinBalance: 5,
    bestDistance: 120,
    ownedSkins: ["green", "red"],
    selectedSkin: "red",
    upgradeLevels: { engine: 2, fuel: 1 }
  });
});
