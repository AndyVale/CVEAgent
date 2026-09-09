"use strict";

(() => {
  class ApiError extends Error {
    constructor(message, {status = null, transient = false, connectivity = false} = {}) {
      super(message);
      this.name = "ApiError";
      this.status = status;
      this.transient = transient;
      this.connectivity = connectivity;
    }
  }

  async function request(path, options = {}) {
    let response;
    try {
      response = await fetch(path, {
        headers: {"Content-Type": "application/json", ...(options.headers || {})},
        ...options,
      });
    } catch (error) {
      throw new ApiError("Could not connect to the local CVE Agent service.", {
        transient: true,
        connectivity: true,
      });
    }
    let body = {};
    try { body = await response.json(); } catch (_) { /* Empty or invalid response. */ }
    if (!response.ok) {
      throw new ApiError(body.error || `Request failed (${response.status})`, {
        status: response.status,
        transient: response.status === 408 || response.status === 429 || response.status >= 500,
      });
    }
    return body;
  }

  globalThis.CVEAgent = globalThis.CVEAgent || {};
  globalThis.CVEAgent.api = {ApiError, request};
})();
