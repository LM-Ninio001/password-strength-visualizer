import { test } from "node:test";
import assert from "node:assert/strict";
import { checkPwned, findSuffixCount, PwnedCheckError, RANGE_URL, sha1Hex } from "../src/pwned.js";

// SHA-1("password") — a well-known test vector.
const PASSWORD_SHA1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8";

test("sha1Hex matches the known vector", async () => {
  assert.equal(await sha1Hex("password"), PASSWORD_SHA1);
});

test("findSuffixCount parses the range response", () => {
  const body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\nFFFF:0";
  assert.equal(findSuffixCount(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8"), 3861493);
  assert.equal(findSuffixCount(body, "ABCDEF"), 0);
});

test("checkPwned sends only the 5-character prefix", async () => {
  const calls = [];
  const fetch = async (url, opts) => {
    calls.push({ url, opts });
    return { ok: true, status: 200, text: async () => "1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\r\n" };
  };
  const count = await checkPwned("password", { fetch });
  assert.equal(count, 42);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, RANGE_URL + "5BAA6");
  assert.ok(!JSON.stringify(calls[0].opts.headers).includes("password"));
});

test("checkPwned returns 0 when the suffix is absent", async () => {
  const fetch = async () => ({ ok: true, status: 200, text: async () => "AAAA:1\r\n" });
  assert.equal(await checkPwned("something-unique", { fetch }), 0);
});

test("checkPwned: network errors become friendly messages", async () => {
  const fetch = async () => {
    throw new TypeError("Failed to fetch");
  };
  await assert.rejects(checkPwned("x", { fetch }), (err) => err instanceof PwnedCheckError && /connection/.test(err.message));
});

test("checkPwned: HTTP errors and rate limits", async () => {
  const status = (s) => async () => ({ ok: false, status: s, text: async () => "" });
  await assert.rejects(checkPwned("x", { fetch: status(503) }), /503/);
  await assert.rejects(checkPwned("x", { fetch: status(429) }), /Too many/);
});

test("checkPwned: empty input is rejected without a request", async () => {
  let called = false;
  const fetch = async () => ((called = true), { ok: true, text: async () => "" });
  await assert.rejects(checkPwned("", { fetch }), PwnedCheckError);
  assert.equal(called, false);
});
