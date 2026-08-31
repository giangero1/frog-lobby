import test from "node:test";
import assert from "node:assert/strict";
import { normalizeFishingState, resolveFishingRoll, startFishing, stopFishing, utcDayKey } from "./fishingLogic.js";

const config = { intervalMs: 90_000, crownChanceBasisPoints: 400, pityRolls: 40, dailyCap: 8 };
const now = Date.UTC(2026, 7, 31, 12, 0, 0);

test("fishing starts with a backend-clock cooldown and stops cleanly", () => {
  const started = startFishing({}, "room-1", now, config);
  assert.equal(started.active, true);
  assert.equal(started.nextEligibleAt, now + 90_000);
  const stopped = stopFishing(started, now);
  assert.equal(stopped.active, false);
  assert.equal(stopped.roomId, "");
});

test("fishing rejects early and mismatched room rolls", () => {
  const state = startFishing({}, "room-1", now, config);
  assert.equal(resolveFishingRoll(state, { nowMs: now + 10, requestId: "r1", roomId: "room-1", config }).error, "too-early");
  assert.equal(resolveFishingRoll(state, { nowMs: now + 90_000, requestId: "r1", roomId: "room-2", config }).error, "not-active");
});

test("fishing chance, pity, duplicate request, and cap are deterministic", () => {
  let state = startFishing({ dryRolls: 38, day: utcDayKey(now) }, "room-1", now, config);
  let decision = resolveFishingRoll(state, { nowMs: now + 90_000, requestId: "r1", roomId: "room-1", randomBasisPoints: 9_999, config });
  assert.equal(decision.result.crownAwarded, 0);
  state = decision.state;
  decision = resolveFishingRoll(state, { nowMs: now + 180_000, requestId: "r2", roomId: "room-1", randomBasisPoints: 9_999, config });
  assert.equal(decision.result.crownAwarded, 1);
  assert.equal(decision.result.pity, true);
  const duplicate = resolveFishingRoll(decision.state, { nowMs: now + 180_001, requestId: "r2", roomId: "room-1", randomBasisPoints: 0, config });
  assert.equal(duplicate.duplicate, true);
  assert.equal(duplicate.result.crownAwarded, 1);

  state = { ...decision.state, awardedToday: 8, dryRolls: 39, nextEligibleAt: now + 270_000 };
  decision = resolveFishingRoll(state, { nowMs: now + 270_000, requestId: "r3", roomId: "room-1", randomBasisPoints: 0, config });
  assert.equal(decision.result.crownAwarded, 0);
  assert.equal(decision.result.capped, true);
});

test("fishing daily counters reset on the next UTC day", () => {
  const nextDay = now + 24 * 60 * 60 * 1000;
  const state = normalizeFishingState({ day: utcDayKey(now), awardedToday: 8, dryRolls: 39 }, nextDay);
  assert.equal(state.awardedToday, 0);
  assert.equal(state.dryRolls, 0);
});
