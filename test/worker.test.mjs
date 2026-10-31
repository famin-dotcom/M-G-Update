import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import test from "node:test";
import worker from "../src/index.mjs";

const password = "test-only-update-password";

async function passwordHash(value) {
  const iterations = 100_000;
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const key = await webcrypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(value),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const derived = new Uint8Array(
    await webcrypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations },
      key,
      256,
    ),
  );
  return `pbkdf2-sha256$${iterations}$${Buffer.from(salt).toString("base64")}$${Buffer.from(derived).toString("base64")}`;
}

function makeEnv({ allowed = true, hash = null } = {}) {
  return {
    AUTH_LIMITER: {
      async limit() {
        return { success: allowed };
      },
    },
    GITHUB_REPOSITORY: "test-owner/test-repo",
    GITHUB_ASSET_NAME: "update.apk",
    GITHUB_TOKEN: "test-token",
    UPDATE_PASSWORD_HASH: hash,
  };
}

function downloadRequest(value = password) {
  return new Request("https://worker.example/download", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "CF-Connecting-IP": "192.0.2.10",
    },
    body: JSON.stringify({ password: value }),
  });
}

test("rejects invalid methods and paths", async () => {
  const env = makeEnv();
  const wrongMethod = await worker.fetch(new Request("https://worker.example/download"), env);
  const wrongPath = await worker.fetch(
    new Request("https://worker.example/private", { method: "POST" }),
    env,
  );
  assert.equal(wrongMethod.status, 405);
  assert.equal(wrongPath.status, 404);
});

test("rejects invalid passwords without contacting GitHub", async (t) => {
  const originalFetch = globalThis.fetch;
  let upstreamCalls = 0;
  globalThis.fetch = async () => {
    upstreamCalls += 1;
    throw new Error("Unexpected upstream request");
  };
  t.after(() => {
    globalThis.fetch = originalFetch;
  });

  const env = makeEnv({ hash: await passwordHash(password) });
  const response = await worker.fetch(downloadRequest("wrong-password"), env);
  assert.equal(response.status, 401);
  assert.equal(upstreamCalls, 0);
});

test("rate limits attempts before password verification", async (t) => {
  const originalFetch = globalThis.fetch;
  let upstreamCalls = 0;
  globalThis.fetch = async () => {
    upstreamCalls += 1;
    throw new Error("Unexpected upstream request");
  };
  t.after(() => {
    globalThis.fetch = originalFetch;
  });

  const response = await worker.fetch(
    downloadRequest(),
    makeEnv({ allowed: false, hash: await passwordHash(password) }),
  );
  assert.equal(response.status, 429);
  assert.equal(response.headers.get("Retry-After"), "60");
  assert.equal(upstreamCalls, 0);
});

test("logs rate limiter failures without exposing request data", async (t) => {
  const originalError = console.error;
  const logged = [];
  console.error = (...values) => logged.push(values);
  t.after(() => {
    console.error = originalError;
  });

  const env = makeEnv({ hash: await passwordHash(password) });
  env.AUTH_LIMITER.limit = async () => {
    throw new Error("sensitive diagnostic detail");
  };
  const response = await worker.fetch(downloadRequest(), env);

  assert.equal(response.status, 503);
  assert.deepEqual(logged, [["Update rate limiter check failed"]]);
});

test("logs invalid password verifier format without exposing values", async (t) => {
  const originalError = console.error;
  const logged = [];
  console.error = (...values) => logged.push(values);
  t.after(() => {
    console.error = originalError;
  });

  const response = await worker.fetch(downloadRequest(), makeEnv({ hash: "invalid" }));

  assert.equal(response.status, 503);
  assert.deepEqual(logged, [["Update password verification failed", "UpdatePasswordHashFormatError"]]);
});

test("rejects PBKDF2 iteration counts above the Worker runtime limit", async (t) => {
  const originalError = console.error;
  const logged = [];
  console.error = (...values) => logged.push(values);
  t.after(() => {
    console.error = originalError;
  });

  const response = await worker.fetch(
    downloadRequest(),
    makeEnv({ hash: "pbkdf2-sha256$200000$invalid$invalid" }),
  );

  assert.equal(response.status, 503);
  assert.deepEqual(logged, [["Update password verification failed", "UpdatePasswordHashIterationsError"]]);
});

test("streams the private APK without forwarding the GitHub token to the asset host", async (t) => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (input, init = {}) => {
    const url = new URL(input);
    calls.push({
      host: url.hostname,
      path: url.pathname,
      authorization: init.headers?.Authorization,
      userAgent: init.headers?.["User-Agent"],
    });
    if (url.pathname.endsWith("/repos/test-owner/test-repo/releases/latest")) {
      return Response.json({
        assets: [{ id: 42, name: "update.apk", state: "uploaded" }],
      });
    }
    if (url.pathname.endsWith("/repos/test-owner/test-repo/releases/assets/42")) {
      return new Response(null, {
        status: 302,
        headers: { Location: "https://release-assets.githubusercontent.com/release.apk?token=short-lived" },
      });
    }
    if (url.hostname === "release-assets.githubusercontent.com") {
      return new Response(new Uint8Array([0x50, 0x4b, 0x03, 0x04]), {
        status: 200,
        headers: { "Content-Length": "4" },
      });
    }
    throw new Error("Unexpected upstream URL");
  };
  t.after(() => {
    globalThis.fetch = originalFetch;
  });

  const response = await worker.fetch(
    downloadRequest(),
    makeEnv({ hash: await passwordHash(password) }),
  );
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("Content-Type"), "application/vnd.android.package-archive");
  assert.deepEqual(
    Array.from(new Uint8Array(await response.arrayBuffer())),
    [0x50, 0x4b, 0x03, 0x04],
  );
  assert.equal(calls.length, 3);
  assert.equal(calls[0].userAgent, "UpdateGateway");
  assert.equal(calls[1].userAgent, "UpdateGateway");
  assert.equal(calls[0].authorization, "Bearer test-token");
  assert.equal(calls[1].authorization, "Bearer test-token");
  assert.equal(calls[2].authorization, undefined);
  assert.equal(calls[2].userAgent, undefined);
});

test("logs GitHub release lookup status without exposing credentials", async (t) => {
  const originalFetch = globalThis.fetch;
  const originalError = console.error;
  const logged = [];
  globalThis.fetch = async () => new Response(null, { status: 403 });
  console.error = (...values) => logged.push(values);
  t.after(() => {
    globalThis.fetch = originalFetch;
    console.error = originalError;
  });

  const response = await worker.fetch(
    downloadRequest(),
    makeEnv({ hash: await passwordHash(password) }),
  );

  assert.equal(response.status, 502);
  assert.deepEqual(logged, [["Private update download failed", "GitHubReleaseLookupHTTP403Error"]]);
});

test("classifies GitHub fine-grained token permission failures safely", async (t) => {
  const originalFetch = globalThis.fetch;
  const originalError = console.error;
  const logged = [];
  globalThis.fetch = async () =>
    Response.json(
      { message: "Resource not accessible by personal access token" },
      { status: 403 },
    );
  console.error = (...values) => logged.push(values);
  t.after(() => {
    globalThis.fetch = originalFetch;
    console.error = originalError;
  });

  const response = await worker.fetch(
    downloadRequest(),
    makeEnv({ hash: await passwordHash(password) }),
  );

  assert.equal(response.status, 502);
  assert.deepEqual(logged, [["Private update download failed", "GitHubTokenPermissionDeniedError"]]);
});

test("classifies GitHub User-Agent policy failures safely", async (t) => {
  const originalFetch = globalThis.fetch;
  const originalError = console.error;
  const logged = [];
  globalThis.fetch = async () =>
    Response.json(
      { message: "Request forbidden by administrative rules. Please make sure your request has a User-Agent header." },
      { status: 403 },
    );
  console.error = (...values) => logged.push(values);
  t.after(() => {
    globalThis.fetch = originalFetch;
    console.error = originalError;
  });

  const response = await worker.fetch(
    downloadRequest(),
    makeEnv({ hash: await passwordHash(password) }),
  );

  assert.equal(response.status, 502);
  assert.deepEqual(logged, [["Private update download failed", "GitHubUserAgentRequiredError"]]);
});

test("classifies GitHub rate limits without logging response details", async (t) => {
  const originalFetch = globalThis.fetch;
  const originalError = console.error;
  const logged = [];
  globalThis.fetch = async () =>
    Response.json(
      { message: "API rate limit exceeded for 192.0.2.1" },
      { status: 403, headers: { "X-RateLimit-Remaining": "0" } },
    );
  console.error = (...values) => logged.push(values);
  t.after(() => {
    globalThis.fetch = originalFetch;
    console.error = originalError;
  });

  const response = await worker.fetch(
    downloadRequest(),
    makeEnv({ hash: await passwordHash(password) }),
  );

  assert.equal(response.status, 502);
  assert.deepEqual(logged, [["Private update download failed", "GitHubRateLimitExceededError"]]);
});

test("classifies GitHub SSO requirements without logging response details", async (t) => {
  const originalFetch = globalThis.fetch;
  const originalError = console.error;
  const logged = [];
  globalThis.fetch = async () =>
    new Response(null, {
      status: 403,
      headers: { "X-GitHub-SSO": "required; url=https://github.com/" },
    });
  console.error = (...values) => logged.push(values);
  t.after(() => {
    globalThis.fetch = originalFetch;
    console.error = originalError;
  });

  const response = await worker.fetch(
    downloadRequest(),
    makeEnv({ hash: await passwordHash(password) }),
  );

  assert.equal(response.status, 502);
  assert.deepEqual(
    logged,
    [["Private update download failed", "GitHubSSOAuthorizationRequiredError"]],
  );
});

test("reports GitHub release lookup redirects without following them", async (t) => {
  const originalFetch = globalThis.fetch;
  const originalError = console.error;
  const logged = [];
  globalThis.fetch = async (input, init = {}) => {
    assert.equal(new URL(input).hostname, "api.github.com");
    assert.equal(init.redirect, "manual");
    return new Response(null, {
      status: 302,
      headers: { Location: "https://github.com/" },
    });
  };
  console.error = (...values) => logged.push(values);
  t.after(() => {
    globalThis.fetch = originalFetch;
    console.error = originalError;
  });

  const response = await worker.fetch(
    downloadRequest(),
    makeEnv({ hash: await passwordHash(password) }),
  );

  assert.equal(response.status, 502);
  assert.deepEqual(logged, [["Private update download failed", "GitHubReleaseLookupHTTP302Error"]]);
});

test("logs GitHub release lookup network failures without exposing error details", async (t) => {
  const originalFetch = globalThis.fetch;
  const originalError = console.error;
  const logged = [];
  globalThis.fetch = async () => {
    throw new TypeError("Sensitive request details");
  };
  console.error = (...values) => logged.push(values);
  t.after(() => {
    globalThis.fetch = originalFetch;
    console.error = originalError;
  });

  const response = await worker.fetch(
    downloadRequest(),
    makeEnv({ hash: await passwordHash(password) }),
  );

  assert.equal(response.status, 502);
  assert.deepEqual(logged, [["Private update download failed", "GitHubReleaseLookupNetworkError"]]);
});

test("logs GitHub asset API network failures without exposing error details", async (t) => {
  const originalFetch = globalThis.fetch;
  const originalError = console.error;
  const logged = [];
  globalThis.fetch = async (input) => {
    const url = new URL(input);
    if (url.pathname.endsWith("/releases/latest")) {
      return Response.json({
        assets: [{ id: 42, name: "update.apk", state: "uploaded" }],
      });
    }
    throw new TypeError("Sensitive request details");
  };
  console.error = (...values) => logged.push(values);
  t.after(() => {
    globalThis.fetch = originalFetch;
    console.error = originalError;
  });

  const response = await worker.fetch(
    downloadRequest(),
    makeEnv({ hash: await passwordHash(password) }),
  );

  assert.equal(response.status, 502);
  assert.deepEqual(logged, [["Private update download failed", "GitHubAssetRequestNetworkError"]]);
});

test("logs GitHub asset download network failures without exposing error details", async (t) => {
  const originalFetch = globalThis.fetch;
  const originalError = console.error;
  const logged = [];
  globalThis.fetch = async (input) => {
    const url = new URL(input);
    if (url.pathname.endsWith("/releases/latest")) {
      return Response.json({
        assets: [{ id: 42, name: "update.apk", state: "uploaded" }],
      });
    }
    if (url.pathname.endsWith("/releases/assets/42")) {
      return new Response(null, {
        status: 302,
        headers: { Location: "https://release-assets.githubusercontent.com/release.apk" },
      });
    }
    throw new TypeError("Sensitive request details");
  };
  console.error = (...values) => logged.push(values);
  t.after(() => {
    globalThis.fetch = originalFetch;
    console.error = originalError;
  });

  const response = await worker.fetch(
    downloadRequest(),
    makeEnv({ hash: await passwordHash(password) }),
  );

  assert.equal(response.status, 502);
  assert.deepEqual(logged, [["Private update download failed", "GitHubAssetDownloadNetworkError"]]);
});

test("rejects redirect targets outside GitHub's asset domain", async (t) => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input) => {
    const url = new URL(input);
    if (url.pathname.endsWith("/repos/test-owner/test-repo/releases/latest")) {
      return Response.json({
        assets: [{ id: 42, name: "update.apk", state: "uploaded" }],
      });
    }
    return new Response(null, {
      status: 302,
      headers: { Location: "https://attacker.example/file.apk" },
    });
  };
  t.after(() => {
    globalThis.fetch = originalFetch;
  });

  const response = await worker.fetch(
    downloadRequest(),
    makeEnv({ hash: await passwordHash(password) }),
  );
  assert.equal(response.status, 502);
});
