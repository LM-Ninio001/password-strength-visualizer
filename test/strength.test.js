import { test } from "node:test";
import assert from "node:assert/strict";
import {
  analyze,
  checklist,
  classify,
  composition,
  crackSeconds,
  estimateEntropy,
  formatDuration,
  poolSize,
  strengthLevel,
  LEVELS,
} from "../src/strength.js";

const close = (actual, expected, eps = 1e-9) =>
  assert.ok(Math.abs(actual - expected) < eps, `${actual} ≉ ${expected}`);

test("classify and composition", () => {
  assert.equal(classify("a"), "lowercase");
  assert.equal(classify("Z"), "uppercase");
  assert.equal(classify("7"), "digits");
  assert.equal(classify("#"), "symbols");
  assert.equal(classify(" "), "symbols");
  assert.equal(classify("é"), "other");
  assert.equal(classify("🔒"), "other");
  assert.deepEqual(composition("aB3$🔒"), { lowercase: 1, uppercase: 1, digits: 1, symbols: 1, other: 1 });
});

test("poolSize adds up the classes in use", () => {
  assert.equal(poolSize(""), 0);
  assert.equal(poolSize("abc"), 26);
  assert.equal(poolSize("aB"), 52);
  assert.equal(poolSize("aB3"), 62);
  assert.equal(poolSize("aB3!"), 95);
  assert.equal(poolSize("aB3!é"), 195);
});

test("entropy: length × log2(pool) when there are no patterns", () => {
  const pw = "vT9#qLz!mR2w";
  const { bits, baseBits, penalty, used } = estimateEntropy(pw);
  close(baseBits, 12 * Math.log2(95));
  close(bits, baseBits);
  assert.equal(penalty, 0);
  assert.deepEqual(used, []);
});

test("entropy: patterns are penalised", () => {
  const plain = estimateEntropy("xkqmzvbt");
  const withWord = estimateEntropy("password");
  assert.ok(withWord.bits < 1, "rank 1 password is ~0 bits");
  assert.ok(withWord.penalty > 30);
  assert.ok(plain.bits > 30);
});

test("entropy: pattern cost replaces only the matched segment", () => {
  // "qwerty" is a keyboard walk / common word; the 4 random chars still count fully.
  const { bits, used } = estimateEntropy("qwertyZx9!");
  assert.ok(used.length >= 1);
  assert.ok(bits > 4 * Math.log2(95) - 1e-9);
  assert.ok(bits < 10 * Math.log2(95));
});

test("entropy: never higher than the base estimate", () => {
  for (const pw of ["Summer2024!", "p@ssw0rd", "aaaaaa", "abcdef123", "Tr0ub4dor&3"]) {
    const e = estimateEntropy(pw);
    assert.ok(e.bits <= e.baseBits + 1e-9, pw);
    assert.ok(e.bits >= 0, pw);
  }
});

test("crackSeconds: average is half the search space", () => {
  assert.equal(crackSeconds(0, 100), 0);
  assert.equal(crackSeconds(1, 1), 1);
  assert.equal(crackSeconds(11, 1024), 1);
  close(crackSeconds(40, 1e10), 2 ** 39 / 1e10);
});

test("formatDuration: plain words", () => {
  assert.equal(formatDuration(0), "instantly");
  assert.equal(formatDuration(0.2), "less than a second");
  assert.equal(formatDuration(1), "1 second");
  assert.equal(formatDuration(45), "45 seconds");
  assert.equal(formatDuration(60), "1 minute");
  assert.equal(formatDuration(3 * 3600), "3 hours");
  assert.equal(formatDuration(2 * 86400), "2 days");
  assert.equal(formatDuration(400 * 31557600), "400 years");
  assert.equal(formatDuration(5_000 * 31557600), "5 thousand years");
  assert.equal(formatDuration(2e6 * 31557600), "2 million years");
  assert.equal(formatDuration(Infinity), "longer than the universe will exist");
  assert.equal(formatDuration(1e30), "longer than the universe will exist");
});

test("formatDuration: rounding rolls over to the next unit", () => {
  assert.equal(formatDuration(59.6), "1 minute");
  assert.equal(formatDuration(3599), "1 hour");
});

test("strengthLevel thresholds", () => {
  assert.equal(strengthLevel(0), 0);
  assert.equal(strengthLevel(27.9), 0);
  assert.equal(strengthLevel(28), 1);
  assert.equal(strengthLevel(45), 2);
  assert.equal(strengthLevel(65), 3);
  assert.equal(strengthLevel(128), 4);
  assert.equal(strengthLevel(128, true), 0, "a known common password is always very weak");
  assert.equal(LEVELS.length, 5);
});

test("checklist", () => {
  const all = checklist("Abcdefghij1!", []);
  assert.deepEqual(all, { length: true, lowercase: true, uppercase: true, number: true, symbol: true, notCommon: true });
  const none = checklist("", []);
  assert.equal(none.length, false);
  assert.equal(none.notCommon, false, "empty input isn't credited as 'not common'");
  assert.equal(checklist("password", [{ type: "common" }]).notCommon, false);
});

test("analyze: empty input", () => {
  const r = analyze("");
  assert.equal(r.length, 0);
  assert.equal(r.entropy, 0);
  assert.equal(r.level, 0);
  assert.equal(r.label, "No password");
  assert.equal(r.crackTimes.online.text, "instantly");
  assert.deepEqual(r.patterns, []);
  assert.equal(r.tips.length, 1);
});

test("analyze: null and undefined are treated as empty", () => {
  assert.equal(analyze(undefined).length, 0);
  assert.equal(analyze(null).length, 0);
});

test("analyze: common passwords are very weak", () => {
  for (const pw of ["password", "123456", "qwerty", "P@ssw0rd"]) {
    const r = analyze(pw);
    assert.equal(r.level, 0, pw);
    assert.equal(r.checks.notCommon, false, pw);
    assert.ok(r.crackTimes.offline.seconds < 1, pw);
  }
});

test("analyze: patterns are reported with types", () => {
  const types = new Set(analyze("qwerty1998aaaa").patterns.map((p) => p.type));
  for (const t of ["keyboard", "date", "repeat"]) assert.ok(types.has(t), t);
});

test("analyze: tips respond to the input", () => {
  assert.ok(analyze("abc").tips.some((t) => /Add 9 more characters/.test(t)));
  assert.ok(analyze("asdfghjk").tips.some((t) => /keyboard/i.test(t)));
  assert.ok(analyze("Summer1998xyz").tips.some((t) => /dates/i.test(t)));
  const strong = analyze("cX7$kq!Vz9#mLp2&Wr4@");
  assert.equal(strong.level, 4);
  assert.match(strong.tips[0], /very strong/i);
});

test("analyze: strong random password", () => {
  const r = analyze("cX7$kq!Vz9#mLp2&Wr4@");
  assert.ok(r.entropy > 120);
  assert.equal(r.label, "Very strong");
  assert.notEqual(r.crackTimes.offline.text, "instantly");
});

test("analyze: emoji and unicode count as single characters", () => {
  const r = analyze("🔒🔑🌍é");
  assert.equal(r.length, 4);
  assert.equal(r.composition.other, 4);
  assert.equal(r.poolSize, 100);
  close(r.entropy, 4 * Math.log2(100));
  assert.equal(r.checks.symbol, true, "emoji count as symbols for the checklist");
});

test("analyze: combining characters and astral letters don't crash", () => {
  const r = analyze("é𝒜漢字🏳️‍🌈");
  assert.ok(r.length > 0);
  assert.ok(Number.isFinite(r.entropy));
});

test("analyze: very long input stays fast and finite", () => {
  const long = "aB3$".repeat(2500); // 10,000 characters
  const start = performance.now();
  const r = analyze(long);
  const ms = performance.now() - start;
  assert.equal(r.length, 10000);
  assert.ok(Number.isFinite(r.entropy));
  assert.equal(r.level, 4);
  assert.ok(ms < 2000, `took ${ms}ms`);
  assert.equal(r.crackTimes.offline.text, "longer than the universe will exist");
});

test("analyze: one long repeated character is weak despite its length", () => {
  const r = analyze("a".repeat(500));
  assert.ok(r.entropy < 20);
  assert.equal(r.level, 0);
});

test("analyze: passphrases are scored by words, not letters", () => {
  const r = analyze("otterpianocomet");
  assert.ok(r.baseEntropy > 70, "15 random lowercase letters would be ~70 bits");
  assert.ok(r.entropy < 30, "three list words are ~27 bits");
});
