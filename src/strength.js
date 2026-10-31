// Pure password-strength logic. No DOM, no network, no storage: every function
// takes a password string and returns plain data, so it is easy to test.

import { detectAll } from "./patterns.js";

export const ATTACKS = {
  online: { label: "Online attack (throttled)", guessesPerSecond: 100 },
  offline: { label: "Offline attack (fast hash)", guessesPerSecond: 1e10 },
};

export const LEVELS = ["Very weak", "Weak", "Fair", "Strong", "Very strong"];
/** Minimum entropy in bits for each level above "Very weak". */
const LEVEL_THRESHOLDS = [28, 40, 60, 80];

export const MIN_LENGTH = 12;

const POOLS = { lowercase: 26, uppercase: 26, digits: 10, symbols: 33, other: 100 };

/** Splits into Unicode code points so an emoji counts as one character, not two. */
export const toChars = (password) => Array.from(password ?? "");

/** Which character class a single code point belongs to. */
export function classify(ch) {
  if (/^[a-z]$/.test(ch)) return "lowercase";
  if (/^[A-Z]$/.test(ch)) return "uppercase";
  if (/^[0-9]$/.test(ch)) return "digits";
  if (/^[\x20-\x7e]$/.test(ch)) return "symbols";
  return "other";
}

/** Counts of each character class, for the composition chart. */
export function composition(password) {
  const counts = { lowercase: 0, uppercase: 0, digits: 0, symbols: 0, other: 0 };
  for (const ch of toChars(password)) counts[classify(ch)]++;
  return counts;
}

/** Size of the alphabet an attacker would have to search, given the classes used. */
export function poolSize(password) {
  const counts = composition(password);
  return Object.keys(POOLS).reduce((sum, k) => sum + (counts[k] > 0 ? POOLS[k] : 0), 0);
}

/*
 * Entropy maths
 * -------------
 * A password of length L drawn uniformly from a pool of N characters has
 * N^L possibilities, i.e. log2(N^L) = L × log2(N) bits of entropy.
 *
 * Real passwords are not uniform, so we also look for patterns (common words,
 * keyboard walks, dates...). Each pattern has its own, much smaller, guess
 * cost in bits (e.g. "password" is rank 1 in the common list ≈ 0 bits).
 * We then find the cheapest way to cover the whole password with either
 * single characters (log2(N) bits each) or pattern matches, using dynamic
 * programming over positions:
 *
 *   best[0] = 0
 *   best[i] = min( best[i-1] + log2(N),                     // one random char
 *                  best[m.start] + m.bits  for each m ending at i )  // a pattern
 *
 * best[L] is the reported entropy; L × log2(N) − best[L] is the pattern penalty.
 */
export function estimateEntropy(password) {
  const chars = toChars(password);
  const n = chars.length;
  const pool = poolSize(password);
  if (n === 0 || pool === 0) return { bits: 0, baseBits: 0, penalty: 0, used: [], patterns: [] };

  const perChar = Math.log2(pool);
  const patterns = detectAll(chars);
  const byEnd = new Map();
  for (const m of patterns) {
    if (!byEnd.has(m.end)) byEnd.set(m.end, []);
    byEnd.get(m.end).push(m);
  }

  const best = new Float64Array(n + 1);
  const choice = new Array(n + 1).fill(null);
  for (let i = 1; i <= n; i++) {
    best[i] = best[i - 1] + perChar;
    for (const m of byEnd.get(i) ?? []) {
      const cost = best[m.start] + m.bits;
      if (cost < best[i]) {
        best[i] = cost;
        choice[i] = m;
      }
    }
  }

  const used = [];
  for (let i = n; i > 0; ) {
    const m = choice[i];
    if (m) {
      used.unshift(m);
      i = m.start;
    } else {
      i--;
    }
  }

  const baseBits = n * perChar;
  // Summing log2(N) n times can drift a hair above n × log2(N); clamp so the
  // pattern penalty is never negative.
  const bits = Math.min(best[n], baseBits);
  return { bits, baseBits, penalty: baseBits - bits, used, patterns };
}

/** Average guesses needed is half the search space: 2^(bits − 1). */
export function crackSeconds(bits, guessesPerSecond) {
  if (bits <= 0) return 0;
  return 2 ** (bits - 1) / guessesPerSecond;
}

const UNITS = [
  ["second", 1],
  ["minute", 60],
  ["hour", 3600],
  ["day", 86400],
  ["month", 2629800],
  ["year", 31557600],
];
const BIG_YEARS = [
  ["thousand", 1e3],
  ["million", 1e6],
  ["billion", 1e9],
  ["trillion", 1e12],
];

/** Formats a duration in plain words: "instantly", "3 hours", "400 years", "2 million years". */
export function formatDuration(seconds) {
  if (!Number.isFinite(seconds)) return "longer than the universe will exist";
  if (seconds < 1) return seconds <= 0 ? "instantly" : "less than a second";

  const years = seconds / 31557600;
  if (years >= 1000) {
    for (let i = BIG_YEARS.length - 1; i >= 0; i--) {
      const [word, size] = BIG_YEARS[i];
      if (years >= size) {
        const value = Math.round(years / size);
        if (word === "trillion" && value >= 1000) return "longer than the universe will exist";
        return `${value} ${word} years`;
      }
    }
  }

  for (let i = UNITS.length - 1; i >= 0; i--) {
    const [unit, size] = UNITS[i];
    if (seconds >= size) {
      const value = Math.round(seconds / size);
      // Rounding can produce "12 months" or "60 minutes"; bump to the next unit.
      const next = UNITS[i + 1];
      if (next && value * size >= next[1]) return plural(Math.round(seconds / next[1]), next[0]);
      return plural(value, unit);
    }
  }
  return "less than a second";
}

const plural = (n, unit) => `${n} ${unit}${n === 1 ? "" : "s"}`;

/** Maps entropy (and whether the whole thing is a known password) to a 0–4 level. */
export function strengthLevel(bits, isCommon = false) {
  if (isCommon) return 0;
  let level = 0;
  for (const t of LEVEL_THRESHOLDS) if (bits >= t) level++;
  return level;
}

/** The live checklist shown in the UI. */
export function checklist(password, patterns = []) {
  const chars = toChars(password);
  return {
    length: chars.length >= MIN_LENGTH,
    lowercase: chars.some((c) => /\p{Ll}/u.test(c)),
    uppercase: chars.some((c) => /\p{Lu}/u.test(c)),
    number: chars.some((c) => /\p{Nd}/u.test(c)),
    symbol: chars.some((c) => !/[\p{L}\p{Nd}]/u.test(c)),
    notCommon: chars.length > 0 && !patterns.some((p) => p.type === "common" || p.type === "leet"),
  };
}

const PATTERN_TIPS = {
  common: "Avoid common passwords and words found in password lists",
  leet: "Swapping letters for look-alikes (p@ssw0rd) doesn't fool attackers",
  keyboard: "Avoid keyboard patterns like qwerty or asdf",
  repeat: "Avoid repeated characters like aaa or 111",
  sequence: "Avoid sequences like abcd or 6789",
  date: "Avoid years and dates; they're among the first things attackers try",
  word: "Dictionary words are guessed whole; use more of them or mix in random characters",
};

/** Plain-English suggestions, most important first. */
export function tips(password, { checks, patterns, level }) {
  const n = toChars(password).length;
  if (n === 0) return ["Start typing to see how strong your password is"];

  const out = [];
  const types = new Set(patterns.map((p) => p.type));
  if (types.has("common") && patterns.some((p) => p.type === "common" && p.start === 0 && p.end === n)) {
    out.push("This is one of the most common passwords; choose something else entirely");
  }
  for (const type of Object.keys(PATTERN_TIPS)) if (types.has(type)) out.push(PATTERN_TIPS[type]);
  if (!checks.length) {
    const more = MIN_LENGTH - n;
    out.push(`Add ${more} more character${more === 1 ? "" : "s"}`);
  }
  if (!checks.uppercase) out.push("Add an uppercase letter");
  if (!checks.lowercase) out.push("Add a lowercase letter");
  if (!checks.number) out.push("Add a number");
  if (!checks.symbol) out.push("Add a symbol such as ! or #");
  if (out.length === 0 || level >= 4) {
    out.length = 0;
    out.push(level >= 4 ? "Excellent: this password is very strong" : "Make it longer to make it stronger");
  } else if (level >= 3 && out.length > 0) {
    out.push("Already strong; a few more characters make it even harder to crack");
  }
  return [...new Set(out)].slice(0, 5);
}

/** Everything the UI needs, in one call. */
export function analyze(password) {
  const pw = password ?? "";
  const { bits, baseBits, penalty, patterns } = estimateEntropy(pw);
  const n = toChars(pw).length;
  const isCommon = patterns.some((p) => (p.type === "common" || p.type === "leet") && p.start === 0 && p.end === n);
  const level = n === 0 ? 0 : strengthLevel(bits, isCommon);
  const checks = checklist(pw, patterns);
  const crackTimes = {};
  for (const [key, attack] of Object.entries(ATTACKS)) {
    const seconds = crackSeconds(bits, attack.guessesPerSecond);
    crackTimes[key] = { ...attack, seconds, text: formatDuration(seconds) };
  }
  return {
    length: n,
    poolSize: poolSize(pw),
    entropy: bits,
    baseEntropy: baseBits,
    penalty,
    patterns: dedupePatterns(patterns),
    level,
    label: n === 0 ? "No password" : LEVELS[level],
    checks,
    crackTimes,
    composition: composition(pw),
    tips: tips(pw, { checks, patterns, level }),
  };
}

/** Drops matches fully contained in a longer match of the same type, for display. */
function dedupePatterns(patterns) {
  return patterns
    .filter((p) => p.type !== "separator")
    .filter(
      (p) =>
        !patterns.some(
          (q) => q !== p && q.type === p.type && q.start <= p.start && q.end >= p.end && q.end - q.start > p.end - p.start,
        ),
    )
    .filter((p, i, arr) => arr.findIndex((q) => q.type === p.type && q.start === p.start && q.end === p.end) === i)
    .sort((a, b) => a.start - b.start);
}
