/**
 * PhishGuardAI Official Node.js / JavaScript SDK
 * Zero-dependency client using native Fetch API (Node 18+).
 */

class PhishGuardError extends Error {
  constructor(message, statusCode = null, responseBody = {}) {
    super(statusCode ? `[${statusCode}] ${message}` : message);
    this.name = "PhishGuardError";
    this.statusCode = statusCode;
    this.responseBody = responseBody;
  }
}

class AuthenticationError extends PhishGuardError {
  constructor(message, statusCode = 401, responseBody = {}) {
    super(message, statusCode, responseBody);
    this.name = "AuthenticationError";
  }
}

class RateLimitError extends PhishGuardError {
  constructor(message, statusCode = 429, responseBody = {}) {
    super(message, statusCode, responseBody);
    this.name = "RateLimitError";
  }
}

class InvalidURLError extends PhishGuardError {
  constructor(message, statusCode = 400, responseBody = {}) {
    super(message, statusCode, responseBody);
    this.name = "InvalidURLError";
  }
}

class APIConnectionError extends PhishGuardError {
  constructor(message) {
    super(message, null, {});
    this.name = "APIConnectionError";
  }
}

class PhishGuardClient {
  /**
   * @param {Object} options
   * @param {string} [options.apiKey] - PhishGuard API key (starts with pg_live_... or pg_test_...)
   * @param {string} [options.baseUrl] - API Base URL (defaults to http://127.0.0.1:5000)
   * @param {number} [options.timeout] - Timeout in milliseconds (default: 10000)
   * @param {string} [options.sessionToken] - Developer session bearer token
   */
  constructor(options = {}) {
    this.apiKey = options.apiKey || null;
    this.baseUrl = (options.baseUrl || "http://127.0.0.1:5000").replace(/\/+$/, "");
    this.timeout = options.timeout || 10000;
    this.sessionToken = options.sessionToken || null;
  }

  /**
   * Internal request helper
   * @private
   */
  async _request(endpoint, method = "GET", payload = null, authType = "apiKey") {
    const url = `${this.baseUrl}${endpoint}`;
    const headers = {
      "Content-Type": "application/json",
      "User-Agent": "PhishGuardAI-Node-SDK/1.0",
    };

    if (authType === "apiKey" && this.apiKey) {
      headers["X-API-Key"] = this.apiKey;
    } else if (authType === "session" && this.sessionToken) {
      headers["Authorization"] = `Bearer ${this.sessionToken}`;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(url, {
        method,
        headers,
        body: payload ? JSON.stringify(payload) : undefined,
        signal: controller.signal,
      });

      const bodyText = await response.text();
      let data = {};
      try {
        data = JSON.parse(bodyText);
      } catch (_) {
        data = { raw: bodyText };
      }

      if (!response.ok) {
        const errorMsg = data.error || response.statusText || "Request failed";
        if (response.status === 401) {
          throw new AuthenticationError(errorMsg, response.status, data);
        } else if (response.status === 429) {
          throw new RateLimitError(errorMsg, response.status, data);
        } else if (response.status === 400) {
          throw new InvalidURLError(errorMsg, response.status, data);
        } else {
          throw new PhishGuardError(errorMsg, response.status, data);
        }
      }

      return data;
    } catch (err) {
      if (err.name === "AbortError") {
        throw new APIConnectionError(`Request timed out after ${this.timeout}ms connecting to ${this.baseUrl}`);
      }
      if (err instanceof PhishGuardError) {
        throw err;
      }
      throw new APIConnectionError(`Failed to connect to ${this.baseUrl}: ${err.message}`);
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Scan a target URL for phishing risk and live domain signals.
   * @param {string} url - Target URL to inspect
   * @param {Object} [options]
   * @param {boolean} [options.checkPresence=true] - Verify live DNS and SSL certificate
   * @returns {Promise<Object>}
   */
  async scan(url, options = {}) {
    const checkPresence = options.checkPresence !== false;
    const endpoint = this.apiKey ? "/api/v1/scan" : "/api/scan";
    return await this._request(endpoint, "POST", { url, check_presence: checkPresence }, "apiKey");
  }

  /**
   * Convenience helper: returns boolean indicating whether the URL is a verified threat.
   * @param {string} url
   * @returns {Promise<boolean>}
   */
  async isPhishing(url) {
    const res = await this.scan(url, { checkPresence: false });
    const verdict = (res.verdict || res.standardized_verdict || "").toLowerCase();
    const risk = (res.risk_level || "").toLowerCase();
    return (
      verdict === "phishing" ||
      verdict === "confirmed_malicious" ||
      risk === "high" ||
      risk === "critical"
    );
  }

  /**
   * Convenience helper: returns phishing risk probability [0.0, 1.0].
   * @param {string} url
   * @returns {Promise<number>}
   */
  async getRiskScore(url) {
    const res = await this.scan(url, { checkPresence: false });
    return typeof res.phishing_probability === "number" ? res.phishing_probability : 0.0;
  }

  /**
   * Scan multiple URLs concurrently with controlled concurrency.
   * @param {string[]} urls - Array of URLs to scan
   * @param {Object} [options]
   * @param {number} [options.concurrency=5] - Maximum parallel requests
   * @param {boolean} [options.checkPresence=false]
   * @returns {Promise<Array<Object>>}
   */
  async batchScan(urls, options = {}) {
    const concurrency = Math.max(1, options.concurrency || 5);
    const checkPresence = Boolean(options.checkPresence);
    const results = new Array(urls.length);

    let currentIndex = 0;
    const worker = async () => {
      while (currentIndex < urls.length) {
        const idx = currentIndex++;
        const targetUrl = urls[idx];
        try {
          const res = await this.scan(targetUrl, { checkPresence });
          results[idx] = res;
        } catch (err) {
          results[idx] = { url: targetUrl, success: false, error: err.message };
        }
      }
    };

    const pool = [];
    for (let i = 0; i < Math.min(concurrency, urls.length); i++) {
      pool.push(worker());
    }

    await Promise.all(pool);
    return results;
  }

  /**
   * Get developer account usage and quota statistics.
   * @returns {Promise<Object>}
   */
  async getUsage() {
    return await this._request("/api/v1/user/usage", "GET", null, "session");
  }

  /**
   * List developer API keys.
   * @returns {Promise<Array<Object>>}
   */
  async listKeys() {
    const res = await this._request("/api/v1/keys", "GET", null, "session");
    return res.keys || [];
  }

  /**
   * Create a new API key.
   * @param {Object} [params]
   * @param {string} [params.label="SDK Key"]
   * @param {boolean} [params.isLive=true]
   * @returns {Promise<Object>}
   */
  async createKey(params = {}) {
    const label = params.label || "SDK Key";
    const isLive = params.isLive !== false;
    return await this._request("/api/v1/keys", "POST", { label, is_live: isLive }, "session");
  }

  /**
   * Revoke an existing API key.
   * @param {number} keyId
   * @returns {Promise<boolean>}
   */
  async revokeKey(keyId) {
    const res = await this._request(`/api/v1/keys/${keyId}`, "DELETE", null, "session");
    return Boolean(res.success);
  }
}

module.exports = {
  PhishGuardClient,
  PhishGuardError,
  AuthenticationError,
  RateLimitError,
  InvalidURLError,
  APIConnectionError,
};

