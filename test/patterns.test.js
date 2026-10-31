import { test } from "node:test";
import assert from "node:assert/strict";
import {
  detectCommon,
  detectLeet,
  detectKeyboard,
  detectRepeat,
  detectSequence,
  detectDate,
  detectWord,
  detectSeparator,
} from "../src/patterns.js";
import { COMMON_PASSWORDS } from "../src/data/common-passwords.js";

const c = (s) => Array.from(s);
const tokens = (matches) => matches.map((m) => m.token);

test("common list has ~1,000 unique lowercase entries", () => {
  assert.equal(COMMON_PASSWORDS.length, 1000);
  assert.equal(new Set(COMMON_PASSWORDS).size, 1000);
  assert.ok(COMMON_PASSWORDS.every((p) => p === p.toLowerCase()));
});

test("detectCommon: whole password, any case", () => {
  assert.ok(tokens(detectCommon(c("password"))).includes("password"));
  assert.ok(tokens(detectCommon(c("PassWord"))).includes("PassWord"));
  assert.ok(tokens(detectCommon(c("1234"))).includes("1234"), "4-character entries match");
});

test("detectCommon: words inside a longer password", () => {
  const found = tokens(detectCommon(c("xxdragonxx")));
  assert.ok(found.includes("dragon"));
});

test("detectCommon: rank 1 costs ~0 bits, capitals add a bit", () => {
  const [m] = detectCommon(c("password")).filter((m) => m.token === "password");
  assert.equal(m.bits, 0);
  const [cap] = detectCommon(c("Password")).filter((m) => m.token === "Password");
  assert.equal(cap.bits, 1);
});

test("detectCommon: random strings have no matches", () => {
  assert.deepEqual(detectCommon(c("vT9#qLz")), []);
});

test("detectLeet: p@ssw0rd and friends", () => {
  assert.ok(tokens(detectLeet(c("p@ssw0rd"))).includes("p@ssw0rd"));
  assert.ok(tokens(detectLeet(c("dr4g0n"))).includes("dr4g0n"));
  assert.ok(tokens(detectLeet(c("$h4d0w"))).includes("$h4d0w"));
});

test("detectLeet: needs at least one substitution", () => {
  assert.deepEqual(tokens(detectLeet(c("password"))), []);
});

test("detectLeet: each substitution adds a bit", () => {
  const [m] = detectLeet(c("p@ssw0rd")).filter((m) => m.token === "p@ssw0rd");
  assert.equal(m.bits, 2);
});

test("detectKeyboard: rows forwards and backwards", () => {
  assert.deepEqual(tokens(detectKeyboard(c("qwerty"))), ["qwerty"]);
  assert.deepEqual(tokens(detectKeyboard(c("xxASDFxx"))), ["ASDF"]);
  assert.deepEqual(tokens(detectKeyboard(c("poiu"))), ["poiu"]);
  assert.deepEqual(tokens(detectKeyboard(c("12345"))), ["12345"]);
});

test("detectKeyboard: needs 4+ keys", () => {
  assert.deepEqual(detectKeyboard(c("qwe")), []);
  assert.deepEqual(detectKeyboard(c("qaz")), []);
});

test("detectRepeat: 3+ of the same character", () => {
  assert.deepEqual(tokens(detectRepeat(c("aaaa"))), ["aaaa"]);
  assert.deepEqual(tokens(detectRepeat(c("ab111cd!!!"))), ["111", "!!!"]);
  assert.deepEqual(detectRepeat(c("aabb")), []);
  assert.deepEqual(tokens(detectRepeat(c("🔥🔥🔥"))), ["🔥🔥🔥"], "emoji repeats are one code point each");
});

test("detectSequence: alphabet and number runs, both directions", () => {
  assert.deepEqual(tokens(detectSequence(c("abcd"))), ["abcd"]);
  assert.deepEqual(tokens(detectSequence(c("x6789y"))), ["6789"]);
  assert.deepEqual(tokens(detectSequence(c("zyx"))), ["zyx"]);
  assert.deepEqual(tokens(detectSequence(c("4321"))), ["4321"]);
  assert.deepEqual(tokens(detectSequence(c("ABC"))), ["ABC"]);
});

test("detectSequence: ignores non-runs and mixed kinds", () => {
  assert.deepEqual(detectSequence(c("acegi")), []);
  assert.deepEqual(detectSequence(c("ab")), []);
  assert.deepEqual(detectSequence(c("9:;")), [], "digits do not run into punctuation");
});

test("detectDate: years", () => {
  assert.deepEqual(tokens(detectDate(c("summer1998"))), ["1998"]);
  assert.deepEqual(tokens(detectDate(c("2024"))), ["2024"]);
  assert.deepEqual(detectDate(c("1850")), []);
  assert.deepEqual(detectDate(c("4199812")), [], "a year buried in a longer number is not a year");
});

test("detectDate: full dates", () => {
  assert.ok(tokens(detectDate(c("12/05/1998"))).includes("12/05/1998"));
  assert.ok(tokens(detectDate(c("1998-05-12"))).includes("1998-05-12"));
  assert.ok(tokens(detectDate(c("me25121990"))).includes("25121990"));
  assert.ok(!tokens(detectDate(c("99991998"))).includes("99991998"), "implausible day/month");
});

test("detectDate: indices stay aligned after emoji", () => {
  const [m] = detectDate(c("🙂🙂2001"));
  assert.equal(m.start, 2);
  assert.equal(m.end, 6);
  assert.equal(m.token, "2001");
});

test("detectWord: words from the passphrase list", () => {
  assert.deepEqual(tokens(detectWord(c("Otter-Maple"))), ["Otter", "Maple"]);
  assert.deepEqual(detectWord(c("zq")), []);
});

test("detectSeparator: a repeated separator shares one choice", () => {
  const m = detectSeparator(c("Otter-Maple-Comet"));
  assert.equal(m.length, 2);
  const total = m.reduce((sum, x) => sum + x.bits, 0);
  assert.ok(Math.abs(total - Math.log2(33)) < 1e-9);
  assert.deepEqual(detectSeparator(c("ab-cd")), [], "a single symbol isn't a separator pattern");
  assert.deepEqual(detectSeparator(c("a--b--c")), [], "must sit between letters or digits");
});
