import { test } from "node:test";
import assert from "node:assert/strict";
import { CHARSETS, generatePassphrase, generatePassword, passphraseBits, randomInt } from "../src/generator.js";
import { WORDLIST } from "../src/data/wordlist.js";

/** Runs fn with Math.random booby-trapped, to prove it is never used. */
function withoutMathRandom(fn) {
  const original = Math.random;
  Math.random = () => {
    throw new Error("Math.random must not be used");
  };
  try {
    return fn();
  } finally {
    Math.random = original;
  }
}

test("randomInt stays in range and uses crypto", () => {
  withoutMathRandom(() => {
    for (let i = 0; i < 1000; i++) {
      const n = randomInt(7);
      assert.ok(Number.isInteger(n) && n >= 0 && n < 7);
    }
  });
  assert.throws(() => randomInt(0), RangeError);
});

test("randomInt rejects biased values", () => {
  // A fake source that first returns a value in the biased tail, then 5.
  const values = [2 ** 32 - 1, 5];
  const fake = { getRandomValues: (buf) => ((buf[0] = values.shift()), buf) };
  assert.equal(randomInt(3, fake), 5 % 3);
});

test("generatePassword: length and required character types", () => {
  withoutMathRandom(() => {
    for (let i = 0; i < 50; i++) {
      const pw = generatePassword({ length: 16 });
      assert.equal(pw.length, 16);
      assert.ok([...pw].some((c) => CHARSETS.lowercase.includes(c)));
      assert.ok([...pw].some((c) => CHARSETS.uppercase.includes(c)));
      assert.ok([...pw].some((c) => CHARSETS.digits.includes(c)));
      assert.ok([...pw].some((c) => CHARSETS.symbols.includes(c)));
    }
  });
});

test("generatePassword: respects disabled sets", () => {
  const pw = generatePassword({ length: 40, uppercase: false, symbols: false });
  assert.match(pw, /^[a-z0-9]+$/);
  assert.throws(() => generatePassword({ lowercase: false, uppercase: false, digits: false, symbols: false }));
});

test("generatePassword: produces different results", () => {
  const seen = new Set(Array.from({ length: 20 }, () => generatePassword()));
  assert.equal(seen.size, 20);
});

test("generatePassphrase: words from the list", () => {
  withoutMathRandom(() => {
    const phrase = generatePassphrase({ words: 6, separator: " ", capitalize: false, addNumber: false });
    const parts = phrase.split(" ");
    assert.equal(parts.length, 6);
    for (const w of parts) assert.ok(WORDLIST.includes(w), w);
  });
});

test("generatePassphrase: capitalisation and number suffix", () => {
  const parts = generatePassphrase({ words: 4 }).split("-");
  assert.equal(parts.length, 5);
  for (const w of parts.slice(0, 4)) assert.match(w, /^[A-Z][a-z]+$/);
  assert.match(parts[4], /^\d{1,2}$/);
});

test("word list is unique, lowercase and reasonably large", () => {
  assert.equal(new Set(WORDLIST).size, WORDLIST.length);
  assert.ok(WORDLIST.every((w) => /^[a-z]+$/.test(w)));
  assert.ok(WORDLIST.length >= 400);
});

test("passphraseBits", () => {
  const perWord = Math.log2(WORDLIST.length);
  assert.equal(passphraseBits({ words: 5, addNumber: false }), 5 * perWord);
});
