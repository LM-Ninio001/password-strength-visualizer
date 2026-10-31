// Pattern detectors. Every detector is a pure function that takes an array of
// characters (Unicode code points, already split with Array.from) and returns
// a list of matches: { type, start, end, token, bits }.
//   start/end  code-point indices, end exclusive
//   bits       estimated entropy of the matched segment if an attacker guesses
//              the pattern itself rather than each character independently

import { COMMON_PASSWORDS } from "./data/common-passwords.js";
import { WORDLIST } from "./data/wordlist.js";

const log2 = Math.log2;

/** Rank (1-based) of each common password, for O(1) lookups. */
const COMMON_RANK = new Map(COMMON_PASSWORDS.map((pw, i) => [pw, i + 1]));
const MAX_COMMON_LENGTH = Math.max(...COMMON_PASSWORDS.map((pw) => pw.length));
/** Substrings shorter than this only count when they are the whole password. */
const MIN_WORD_LENGTH = 4;

const KEYBOARD_ROWS = ["1234567890-=", "qwertyuiop[]", "asdfghjkl;'", "zxcvbnm,./"];
/** Number of places a keyboard walk can start, times two directions. */
const KEYBOARD_STARTS = KEYBOARD_ROWS.join("").length * 2;

const LEET = {
  "@": "a", "4": "a", "8": "b", "(": "c", "3": "e", "6": "g", "9": "g",
  "1": "i", "!": "i", "|": "i", "0": "o", "$": "s", "5": "s", "7": "t", "+": "t", "2": "z",
};

const lowerAll = (chars) => chars.map((c) => c.toLowerCase());

/** Common passwords, either the whole input or a word of 4+ characters inside it. */
export function detectCommon(chars) {
  return findDictionaryMatches(lowerAll(chars), chars, "common");
}

const WORDS = new Set(WORDLIST);
const MAX_WORD_LENGTH = Math.max(...WORDLIST.map((w) => w.length));

/**
 * Dictionary words from the passphrase list. An attacker who knows the list
 * guesses whole words, so each costs log2(list size) bits, not ~4.7 per letter.
 */
export function detectWord(chars) {
  const lower = lowerAll(chars);
  const matches = [];
  for (let start = 0; start < lower.length; start++) {
    const maxEnd = Math.min(lower.length, start + MAX_WORD_LENGTH);
    for (let end = start + 3; end <= maxEnd; end++) {
      if (!WORDS.has(lower.slice(start, end).join(""))) continue;
      const token = chars.slice(start, end);
      matches.push({
        type: "word",
        start,
        end,
        token: token.join(""),
        bits: Math.log2(WORDLIST.length) + capitalisationBits(token),
      });
    }
  }
  return matches;
}

/** Common words written in leetspeak, e.g. p@ssw0rd. Only reported if substitution was needed. */
export function detectLeet(chars) {
  const lower = lowerAll(chars);
  const variants = [
    lower.map((c) => LEET[c] ?? c),
    lower.map((c) => (c === "1" ? "l" : LEET[c] ?? c)),
  ];
  const seen = new Set();
  const matches = [];
  for (const normalized of variants) {
    for (const m of findDictionaryMatches(normalized, chars, "leet")) {
      const subs = countDiffs(lower, normalized, m.start, m.end);
      const key = `${m.start}:${m.end}`;
      if (subs === 0 || seen.has(key)) continue;
      seen.add(key);
      // One extra bit per substituted character: each was "swap or don't".
      matches.push({ ...m, bits: m.bits + subs });
    }
  }
  return matches;
}

function findDictionaryMatches(lower, original, type) {
  const matches = [];
  const n = lower.length;
  for (let start = 0; start < n; start++) {
    const maxEnd = Math.min(n, start + MAX_COMMON_LENGTH);
    for (let end = start + 1; end <= maxEnd; end++) {
      const isWhole = start === 0 && end === n;
      if (end - start < MIN_WORD_LENGTH && !isWhole) continue;
      const rank = COMMON_RANK.get(lower.slice(start, end).join(""));
      if (rank === undefined) continue;
      const token = original.slice(start, end);
      matches.push({
        type,
        start,
        end,
        token: token.join(""),
        // Guessing it means walking the list up to its rank, plus one bit
        // for each capitalisation choice an attacker would also try.
        bits: log2(rank) + capitalisationBits(token),
      });
    }
  }
  return matches;
}

function capitalisationBits(token) {
  const upper = token.filter((c) => /[A-Z]/.test(c)).length;
  if (upper === 0) return 0;
  if (upper === token.length || (upper === 1 && /[A-Z]/.test(token[0]))) return 1;
  return upper;
}

function countDiffs(a, b, start, end) {
  let diffs = 0;
  for (let i = start; i < end; i++) if (a[i] !== b[i]) diffs++;
  return diffs;
}

/** Walks along a keyboard row, forwards or backwards, 4+ keys long (qwer, lkjh, 7890). */
export function detectKeyboard(chars) {
  const lower = lowerAll(chars);
  const matches = [];
  for (const row of KEYBOARD_ROWS) {
    for (const dir of [1, -1]) {
      let i = 0;
      while (i < lower.length) {
        let j = i + 1;
        while (j < lower.length && isNextKey(row, lower[j - 1], lower[j], dir)) j++;
        if (j - i >= 4) {
          matches.push({
            type: "keyboard",
            start: i,
            end: j,
            token: chars.slice(i, j).join(""),
            bits: log2(KEYBOARD_STARTS) + log2(j - i),
          });
          i = j;
        } else {
          i++;
        }
      }
    }
  }
  return matches;
}

function isNextKey(row, a, b, dir) {
  const ia = row.indexOf(a);
  return ia !== -1 && row.indexOf(b) === ia + dir;
}

/** The same character three or more times in a row (aaa, 1111, !!!). */
export function detectRepeat(chars) {
  const matches = [];
  let i = 0;
  while (i < chars.length) {
    let j = i + 1;
    while (j < chars.length && chars[j] === chars[i]) j++;
    if (j - i >= 3) {
      matches.push({
        type: "repeat",
        start: i,
        end: j,
        token: chars.slice(i, j).join(""),
        // Pick one character (up to ~100 choices), then how many times to repeat it.
        bits: log2(100) + log2(j - i),
      });
    }
    i = j;
  }
  return matches;
}

/** Alphabet or number runs of 3+, up or down (abc, 6789, zyx, 321). */
export function detectSequence(chars) {
  const lower = lowerAll(chars);
  const matches = [];
  let i = 0;
  while (i < lower.length - 2) {
    const step = code(lower[i + 1]) - code(lower[i]);
    if ((step !== 1 && step !== -1) || !sameKind(lower[i], lower[i + 1])) {
      i++;
      continue;
    }
    let j = i + 2;
    while (j < lower.length && code(lower[j]) - code(lower[j - 1]) === step && sameKind(lower[j - 1], lower[j])) j++;
    if (j - i >= 3) {
      const alphabet = /[0-9]/.test(lower[i]) ? 10 : 26;
      matches.push({
        type: "sequence",
        start: i,
        end: j,
        token: chars.slice(i, j).join(""),
        // Start point, direction, and length.
        bits: log2(alphabet) + 1 + log2(j - i),
      });
      i = j;
    } else {
      i++;
    }
  }
  return matches;
}

const code = (c) => c.codePointAt(0);
function sameKind(a, b) {
  return (/[a-z]/.test(a) && /[a-z]/.test(b)) || (/[0-9]/.test(a) && /[0-9]/.test(b));
}

const YEAR_RE = /(?:19|20)\d\d/g;
// d/m/y, m/d/y, y/m/d with optional separators, or a compact ddmmyyyy / yyyymmdd.
const DATE_RES = [
  /(?<!\d)(\d{1,2})([-/.\s]?)(\d{1,2})\2((?:19|20)\d\d)(?!\d)/g,
  /(?<!\d)((?:19|20)\d\d)([-/.\s]?)(\d{1,2})\2(\d{1,2})(?!\d)/g,
];
// Roughly 365 days × 200 plausible years.
const DATE_BITS = log2(365 * 200);
const YEAR_BITS = log2(200);

/** Years 1900–2099 and full dates such as 12/05/1998 or 19980512. */
export function detectDate(chars) {
  // Regexes run on a string, so only use this on the ASCII-digit view of the input;
  // non-ASCII characters are replaced with a placeholder to keep indices aligned.
  const ascii = chars.map((c) => (c.length === 1 ? c : "\u0000")).join("");
  const matches = [];
  for (const re of DATE_RES) {
    for (const m of ascii.matchAll(re)) {
      const nums = re === DATE_RES[0] ? [m[1], m[3]] : [m[3], m[4]];
      const [a, b] = nums.map(Number);
      const plausible = (a >= 1 && a <= 31 && b >= 1 && b <= 12) || (a >= 1 && a <= 12 && b >= 1 && b <= 31);
      if (!plausible) continue;
      matches.push(span("date", chars, m.index, m.index + m[0].length, DATE_BITS));
    }
  }
  for (const m of ascii.matchAll(YEAR_RE)) {
    const before = ascii[m.index - 1];
    const after = ascii[m.index + 4];
    if (/\d/.test(before ?? "") && /\d/.test(after ?? "")) continue;
    matches.push(span("date", chars, m.index, m.index + 4, YEAR_BITS));
  }
  return matches;
}

function span(type, chars, start, end, bits) {
  return { type, start, end, token: chars.slice(start, end).join(""), bits };
}

/** Runs every detector. Matches may overlap; strength.js picks the cheapest cover. */
export function detectAll(chars) {
  return [
    ...detectCommon(chars),
    ...detectLeet(chars),
    ...detectWord(chars),
    ...detectKeyboard(chars),
    ...detectRepeat(chars),
    ...detectSequence(chars),
    ...detectDate(chars),
  ];
}
