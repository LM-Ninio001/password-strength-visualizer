// "Have I Been Pwned" check using the k-anonymity range API.
// The password is hashed locally with SHA-1; only the first 5 hex characters
// of the hash are sent. The API returns every hash suffix that shares that
// prefix, and the match is done here in the browser.

export const RANGE_URL = "https://api.pwnedpasswords.com/range/";
const TIMEOUT_MS = 8000;

/** Uppercase hex SHA-1 of a string, via Web Crypto. */
export async function sha1Hex(text, crypto = globalThis.crypto) {
  const digest = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

/** Parses "SUFFIX:COUNT" lines and returns the count for `suffix` (0 if absent). */
export function findSuffixCount(body, suffix) {
  for (const line of body.split(/\r?\n/)) {
    const [s, count] = line.trim().split(":");
    if (s && s.toUpperCase() === suffix) return Number.parseInt(count, 10) || 0;
  }
  return 0;
}

export class PwnedCheckError extends Error {}

/**
 * Returns how many times the password appears in known breaches.
 * Throws PwnedCheckError with a user-friendly message on network problems.
 */
export async function checkPwned(password, { fetch = globalThis.fetch, crypto = globalThis.crypto } = {}) {
  if (!password) throw new PwnedCheckError("Enter a password first.");
  const hash = await sha1Hex(password, crypto);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  let response;
  try {
    // Add-Padding makes every response a similar size, so the response
    // length doesn't hint at which prefix was asked for.
    response = await fetch(RANGE_URL + prefix, {
      headers: { "Add-Padding": "true" },
      signal: controller.signal,
      cache: "no-store",
      referrerPolicy: "no-referrer",
    });
  } catch (err) {
    throw new PwnedCheckError(
      err?.name === "AbortError"
        ? "The breach database took too long to answer. Please try again."
        : "Couldn't reach the breach database. Check your connection and try again.",
    );
  } finally {
    clearTimeout(timer);
  }
  if (!response.ok) {
    throw new PwnedCheckError(
      response.status === 429
        ? "Too many checks in a short time. Wait a moment and try again."
        : `The breach database returned an error (${response.status}). Please try again later.`,
    );
  }
  return findSuffixCount(await response.text(), suffix);
}
