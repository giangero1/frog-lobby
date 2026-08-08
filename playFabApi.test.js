import test from "node:test";
import assert from "node:assert/strict";
import { createPlayFabApi } from "./playFabApi.js";

function successfulFetch(calls) {
  return async (url, options) => {
    calls.push({ url, options });
    return {
      ok: true,
      status: 200,
      async text() { return JSON.stringify({ code: 200, data: { ok: true } }); }
    };
  };
}

test("PlayFab client purchase uses Client/PurchaseItem and the player session ticket", async () => {
  const calls = [];
  const api = createPlayFabApi({
    apiBase: "https://ABCD.playfabapi.com",
    secretKey: "server-secret",
    fetchImpl: successfulFetch(calls)
  });
  const body = { CatalogVersion: "Cosmetics", ItemId: "shtreimel", Price: 8, VirtualCurrency: "CR" };

  await api.clientRequest("/Client/PurchaseItem", body, "player-ticket");

  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://ABCD.playfabapi.com/Client/PurchaseItem");
  assert.equal(calls[0].options.headers["X-Authorization"], "player-ticket");
  assert.equal("X-SecretKey" in calls[0].options.headers, false);
  assert.deepEqual(JSON.parse(calls[0].options.body), body);
});

test("PlayFab server requests continue to use the title secret key", async () => {
  const calls = [];
  const api = createPlayFabApi({ apiBase: "https://ABCD.playfabapi.com", secretKey: "server-secret", fetchImpl: successfulFetch(calls) });
  await api.serverRequest("/Server/GetUserInventory", { PlayFabId: "P1" });
  assert.equal(calls[0].options.headers["X-SecretKey"], "server-secret");
  assert.equal("X-Authorization" in calls[0].options.headers, false);
});

test("PlayFab errors retain the service error payload for safe classification", async () => {
  const api = createPlayFabApi({
    apiBase: "https://ABCD.playfabapi.com",
    secretKey: "server-secret",
    fetchImpl: async () => ({
      ok: false,
      status: 400,
      async text() { return JSON.stringify({ code: 400, error: "WrongPrice", errorMessage: "The price changed" }); }
    })
  });
  await assert.rejects(
    api.clientRequest("/Client/PurchaseItem", {}, "player-ticket"),
    error => error.status === 400 && error.playFab.error === "WrongPrice"
  );
});
