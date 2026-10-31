// DOM wiring. All analysis lives in strength.js; this file only renders it.
// The password is never logged, stored, or put in the URL. The only thing
// persisted is the chosen colour theme.

import { analyze, LEVELS } from "./strength.js";
import { generatePassphrase, generatePassword, passphraseBits } from "./generator.js";
import { checkPwned, PwnedCheckError } from "./pwned.js";

const $ = (id) => document.getElementById(id);

const els = {
  input: $("password"),
  toggle: $("toggle-visibility"),
  toggleText: $("visibility-text"),
  copy: $("copy"),
  copyStatus: $("copy-status"),
  strengthLabel: $("strength-label"),
  strengthText: $("strength-text"),
  strengthLevel: $("strength-level"),
  meter: $("meter"),
  meterFill: $("meter-fill"),
  scale: document.querySelectorAll(".meter-scale li"),
  entropy: $("entropy"),
  entropyDetail: $("entropy-detail"),
  timeOnline: $("time-online"),
  timeOffline: $("time-offline"),
  announcer: $("announcer"),
  checklist: $("checklist"),
  tips: $("tips"),
  patterns: $("patterns"),
  patternsEmpty: $("patterns-empty"),
  donutSegments: $("donut-segments"),
  donutTotal: $("donut-total"),
  donutDesc: $("donut-desc"),
  legend: $("legend"),
  theme: $("theme-toggle"),
  leakButton: $("leak-check"),
  leakResult: $("leak-result"),
};

const PATTERN_NAMES = {
  common: "Common password",
  leet: "Leetspeak word",
  word: "Dictionary word",
  keyboard: "Keyboard pattern",
  repeat: "Repeated characters",
  sequence: "Sequence",
  date: "Year or date",
};

const CLASS_NAMES = {
  lowercase: "Lowercase",
  uppercase: "Uppercase",
  digits: "Digits",
  symbols: "Symbols",
  other: "Unicode / emoji",
};

/** Entropy (bits) at each tick of the meter: the level thresholds, then "full". */
const METER_STOPS = [0, 28, 40, 60, 80, 100];
const ANNOUNCE_DELAY_MS = 700;

let lastResult = analyze("");
let announceTimer;
let lastAnnounced = "";

// ---------- Rendering ----------

function render() {
  const result = analyze(els.input.value);
  lastResult = result;
  renderMeter(result);
  renderStats(result);
  renderChecklist(result);
  renderTips(result);
  renderPatterns(result);
  renderComposition(result);
  resetLeakCheck();
  scheduleAnnouncement(result);
}

/** Maps entropy onto 0–1 so each of the five levels fills exactly one fifth of the bar. */
function meterFraction(bits) {
  const segments = METER_STOPS.length - 1;
  for (let i = 0; i < segments; i++) {
    const [lo, hi] = [METER_STOPS[i], METER_STOPS[i + 1]];
    if (bits < hi) return (i + (bits - lo) / (hi - lo)) / segments;
  }
  return 1;
}

function renderMeter({ entropy, level, label, length }) {
  // A known common password is pinned to "Very weak", whatever its raw entropy.
  const fraction = Math.min(meterFraction(entropy), (level + 1) / 5);
  // Hue follows the continuous entropy, so the colour glides from red (0) to green (130).
  const hue = Math.round(fraction * 130);
  document.documentElement.style.setProperty("--strength-hue", String(hue));

  const width = length === 0 ? 0 : Math.max(fraction * 100, 4);
  els.meterFill.style.width = `${width}%`;

  els.strengthText.textContent = label;
  els.strengthLabel.dataset.empty = String(length === 0);
  els.strengthLevel.textContent = length === 0 ? "" : `Level ${level + 1} of ${LEVELS.length}`;
  els.meter.setAttribute("aria-valuenow", String(length === 0 ? 0 : level));
  els.meter.setAttribute("aria-valuetext", length === 0 ? "No password" : `${label}, level ${level + 1} of 5`);
  els.scale.forEach((li, i) => li.classList.toggle("active", length > 0 && i === level));
}

function renderStats({ entropy, baseEntropy, penalty, poolSize, length, crackTimes }) {
  els.entropy.textContent = entropy.toFixed(1).replace(/\.0$/, "");
  els.entropyDetail.textContent =
    length === 0
      ? "Pool × length, minus patterns"
      : penalty > 0.05
        ? `${length} chars × log₂(${poolSize}) = ${baseEntropy.toFixed(1)}, −${penalty.toFixed(1)} for patterns`
        : `${length} chars × log₂(${poolSize}) = ${baseEntropy.toFixed(1)}`;
  els.timeOnline.textContent = crackTimes.online.text;
  els.timeOffline.textContent = crackTimes.offline.text;
}

function renderChecklist({ checks }) {
  for (const li of els.checklist.querySelectorAll("li")) {
    const met = Boolean(checks[li.dataset.check]);
    li.classList.toggle("met", met);
    li.querySelector(".check-state").textContent = met ? "Done: " : "Not yet: ";
  }
}

function renderTips({ tips }) {
  const current = [...els.tips.children].map((li) => li.textContent);
  if (current.join("\n") === tips.join("\n")) return;
  els.tips.replaceChildren(...tips.map((t) => li(t)));
}

function renderPatterns({ patterns }) {
  const visible = els.input.type === "text";
  const items = patterns.map((p) => {
    const item = document.createElement("li");
    item.append(`${PATTERN_NAMES[p.type] ?? p.type}: `);
    if (visible) {
      const code = document.createElement("code");
      code.textContent = p.token;
      item.append(code);
    } else {
      // Don't reveal parts of a hidden password on screen.
      const n = Array.from(p.token).length;
      item.append(`${n} character${n === 1 ? "" : "s"}`);
    }
    return item;
  });
  els.patterns.replaceChildren(...items);
  els.patternsEmpty.hidden = items.length > 0;
}

const CIRCUMFERENCE = 100; // r = 15.915 → circumference ≈ 100, so dash lengths are percentages.

function renderComposition({ composition, length }) {
  els.donutTotal.textContent = String(length);
  const segments = [];
  const legend = [];
  let offset = 0;
  const parts = [];
  for (const [key, count] of Object.entries(composition)) {
    const pct = length ? (count / length) * 100 : 0;
    if (key === "other" && count === 0) continue;
    if (count > 0) {
      const seg = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      seg.setAttribute("class", `donut-seg c-${key}`);
      seg.setAttribute("cx", "21");
      seg.setAttribute("cy", "21");
      seg.setAttribute("r", "15.915");
      seg.setAttribute("stroke-dasharray", `${(pct / 100) * CIRCUMFERENCE} ${CIRCUMFERENCE}`);
      seg.setAttribute("stroke-dashoffset", String(-offset));
      segments.push(seg);
      offset += (pct / 100) * CIRCUMFERENCE;
      parts.push(`${CLASS_NAMES[key]} ${count}`);
    }
    const item = document.createElement("li");
    const swatch = document.createElement("span");
    swatch.className = `swatch c-${key}`;
    swatch.setAttribute("aria-hidden", "true");
    const name = document.createElement("span");
    name.textContent = CLASS_NAMES[key];
    const value = document.createElement("span");
    value.className = "count";
    value.textContent = length ? `${count} · ${Math.round(pct)}%` : "0";
    item.append(swatch, name, value);
    legend.push(item);
  }
  els.donutSegments.replaceChildren(...segments);
  els.legend.replaceChildren(...legend);
  els.donutDesc.textContent = length
    ? `Character mix of ${length} characters: ${parts.join(", ")}`
    : "No characters yet";
}

function scheduleAnnouncement({ label, length }) {
  clearTimeout(announceTimer);
  announceTimer = setTimeout(() => {
    const message = length === 0 ? "" : `Strength: ${label}`;
    if (message && message !== lastAnnounced) {
      els.announcer.textContent = message;
      lastAnnounced = message;
    }
    if (!message) lastAnnounced = "";
  }, ANNOUNCE_DELAY_MS);
}

const li = (text) => {
  const el = document.createElement("li");
  el.textContent = text;
  return el;
};

// ---------- Show / hide and copy ----------

els.toggle.addEventListener("click", () => {
  const show = els.input.type === "password";
  els.input.type = show ? "text" : "password";
  els.toggle.setAttribute("aria-pressed", String(show));
  els.toggleText.textContent = show ? "Hide password" : "Show password";
  renderPatterns(lastResult);
});

let copyTimer;
els.copy.addEventListener("click", async () => {
  clearTimeout(copyTimer);
  if (!els.input.value) {
    flashCopy("Nothing to copy yet.", true);
    return;
  }
  try {
    await navigator.clipboard.writeText(els.input.value);
    flashCopy("Copied to clipboard.");
  } catch {
    flashCopy("Couldn't copy. Your browser blocked clipboard access.", true);
  }
});

function flashCopy(message, isError = false) {
  els.copyStatus.textContent = message;
  els.copyStatus.classList.toggle("error", isError);
  copyTimer = setTimeout(() => (els.copyStatus.textContent = ""), 2500);
}

// ---------- Generator ----------

const gen = {
  modeRandom: $("mode-random"),
  modePassphrase: $("mode-passphrase"),
  optsRandom: $("opts-random"),
  optsPassphrase: $("opts-passphrase"),
  length: $("gen-length"),
  lengthOut: $("length-out"),
  lower: $("gen-lower"),
  upper: $("gen-upper"),
  digits: $("gen-digits"),
  symbols: $("gen-symbols"),
  words: $("gen-words"),
  wordsOut: $("words-out"),
  capitalize: $("gen-capitalize"),
  number: $("gen-number"),
  hint: $("passphrase-hint"),
  button: $("generate"),
  error: $("generate-error"),
};

function syncGeneratorUI() {
  const passphrase = gen.modePassphrase.checked;
  gen.optsRandom.hidden = passphrase;
  gen.optsPassphrase.hidden = !passphrase;
  gen.lengthOut.value = gen.length.value;
  gen.wordsOut.value = gen.words.value;
  const bits = passphraseBits({ words: Number(gen.words.value), addNumber: gen.number.checked });
  gen.hint.textContent = `About ${Math.round(bits)} bits of randomness from the word list. More words are stronger.`;
}

for (const el of [gen.modeRandom, gen.modePassphrase, gen.length, gen.words, gen.number]) {
  el.addEventListener("input", syncGeneratorUI);
}

gen.button.addEventListener("click", () => {
  gen.error.textContent = "";
  try {
    els.input.value = gen.modePassphrase.checked
      ? generatePassphrase({
          words: Number(gen.words.value),
          capitalize: gen.capitalize.checked,
          addNumber: gen.number.checked,
        })
      : generatePassword({
          length: Number(gen.length.value),
          lowercase: gen.lower.checked,
          uppercase: gen.upper.checked,
          digits: gen.digits.checked,
          symbols: gen.symbols.checked,
        });
  } catch (err) {
    gen.error.textContent = err.message;
    return;
  }
  render();
});

// ---------- Leak check ----------

let leakRequest = 0;

function resetLeakCheck() {
  leakRequest++;
  els.leakButton.disabled = els.input.value.length === 0;
  els.leakButton.removeAttribute("aria-busy");
  els.leakButton.textContent = "Check if leaked";
  els.leakResult.textContent = "";
  els.leakResult.className = "leak-result";
}

els.leakButton.addEventListener("click", async () => {
  const request = ++leakRequest;
  els.leakButton.disabled = true;
  els.leakButton.setAttribute("aria-busy", "true");
  els.leakButton.textContent = "Checking…";
  els.leakResult.className = "leak-result";
  els.leakResult.textContent = "Checking breach database…";
  try {
    const count = await checkPwned(els.input.value);
    if (request !== leakRequest) return; // The password changed while we waited.
    if (count > 0) {
      els.leakResult.textContent = `⚠ Found in data breaches ${count.toLocaleString()} time${count === 1 ? "" : "s"}. Don't use this password.`;
      els.leakResult.classList.add("bad");
    } else {
      els.leakResult.textContent = "✓ Not found in known data breaches. That's good, but it doesn't guarantee the password is strong.";
      els.leakResult.classList.add("good");
    }
  } catch (err) {
    if (request !== leakRequest) return;
    els.leakResult.textContent =
      err instanceof PwnedCheckError ? err.message : "Something went wrong while checking. Please try again.";
    els.leakResult.classList.add("bad");
  } finally {
    if (request === leakRequest) {
      els.leakButton.disabled = false;
      els.leakButton.removeAttribute("aria-busy");
      els.leakButton.textContent = "Check again";
    }
  }
});

// ---------- Theme ----------

const THEME_KEY = "psv-theme";

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  els.theme.setAttribute("aria-label", theme === "dark" ? "Switch to light theme" : "Switch to dark theme");
}

els.theme.addEventListener("click", () => {
  const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  applyTheme(next);
  try {
    localStorage.setItem(THEME_KEY, next);
  } catch {
    // Storage can be unavailable (private mode); the toggle still works for this visit.
  }
});

try {
  const saved = localStorage.getItem(THEME_KEY);
  if (saved === "light" || saved === "dark") applyTheme(saved);
} catch {
  // Ignore: fall back to the default dark theme.
}

// ---------- Start ----------

els.input.addEventListener("input", render);
syncGeneratorUI();
render();
