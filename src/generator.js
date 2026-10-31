// Password and passphrase generation. All randomness comes from
// crypto.getRandomValues; Math.random is never used.

import { WORDLIST } from "./data/wordlist.js";

export const CHARSETS = {
  lowercase: "abcdefghijkmnopqrstuvwxyz",
  uppercase: "ABCDEFGHJKLMNPQRSTUVWXYZ",
  digits: "23456789",
  symbols: "!@#$%^&*()-_=+[]{};:,.?/",
};
// Look-alike characters (l, I, O, 0, 1) are left out of the default sets so a
// generated password is easy to read and retype.

/** Uniform random integer in [0, max), using rejection sampling to avoid modulo bias. */
export function randomInt(max, crypto = globalThis.crypto) {
  if (!Number.isInteger(max) || max <= 0 || max > 2 ** 32) throw new RangeError("max must be 1..2^32");
  const limit = 2 ** 32 - (2 ** 32 % max);
  const buf = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) return buf[0] % max;
  }
}

const pick = (str, crypto) => str[randomInt(str.length, crypto)];

/** Fisher–Yates shuffle, in place. */
function shuffle(arr, crypto) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = randomInt(i + 1, crypto);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

/**
 * Random-character password. Guarantees at least one character from every
 * selected set, then shuffles so those aren't always at the front.
 */
export function generatePassword(
  { length = 20, lowercase = true, uppercase = true, digits = true, symbols = true } = {},
  crypto = globalThis.crypto,
) {
  const sets = Object.entries({ lowercase, uppercase, digits, symbols })
    .filter(([, on]) => on)
    .map(([name]) => CHARSETS[name]);
  if (sets.length === 0) throw new Error("Choose at least one character type");
  const len = Math.max(length, sets.length);
  const all = sets.join("");
  const chars = sets.map((s) => pick(s, crypto));
  while (chars.length < len) chars.push(pick(all, crypto));
  return shuffle(chars, crypto).join("");
}

/** Passphrase of random words, e.g. "Otter-Maple-Comet-Violin-7". */
export function generatePassphrase(
  { words = 5, separator = "-", capitalize = true, addNumber = true } = {},
  crypto = globalThis.crypto,
) {
  if (!Number.isInteger(words) || words < 1) throw new RangeError("words must be a positive integer");
  const parts = Array.from({ length: words }, () => {
    const w = WORDLIST[randomInt(WORDLIST.length, crypto)];
    return capitalize ? w[0].toUpperCase() + w.slice(1) : w;
  });
  if (addNumber) parts.push(String(randomInt(100, crypto)));
  return parts.join(separator);
}

/** Entropy of a generated passphrase, from the word list size rather than its characters. */
export function passphraseBits({ words = 5, addNumber = true } = {}) {
  return words * Math.log2(WORDLIST.length) + (addNumber ? Math.log2(100) : 0);
}
