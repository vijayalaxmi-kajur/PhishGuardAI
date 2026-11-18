const assert = require("assert");
const {
  PhishGuardClient,
  PhishGuardError,
  AuthenticationError,
  RateLimitError,
  InvalidURLError,
  APIConnectionError,
} = require("./index.js");

console.log("Testing Node SDK instantiation...");
const client = new PhishGuardClient({
  apiKey: "pg_test_mock123",
  baseUrl: "http://127.0.0.1:5000",
  timeout: 3000,
});

assert.strictEqual(client.baseUrl, "http://127.0.0.1:5000");
assert.strictEqual(client.apiKey, "pg_test_mock123");
assert.strictEqual(typeof client.scan, "function");
assert.strictEqual(typeof client.isPhishing, "function");
assert.strictEqual(typeof client.batchScan, "function");

console.log("Testing error class hierarchy...");
const err = new AuthenticationError("Unauthorized", 401, { error: "bad key" });
assert.ok(err instanceof PhishGuardError);
assert.ok(err instanceof Error);
assert.strictEqual(err.statusCode, 401);

console.log("All Node SDK assertions passed cleanly!");

