const MAX_REQUEST_BYTES = 1024;
const MAX_RELEASE_JSON_BYTES = 1024 * 1024;
const MAX_GITHUB_ERROR_BYTES = 4096;
const MAX_APK_BYTES = 50 * 1024 * 1024;
const MIN_PBKDF2_ITERATIONS = 100_000;
const MAX_PBKDF2_ITERATIONS = 100_000;
const textEncoder = new TextEncoder();

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname !== "/download") {
      return jsonResponse({ error: "not_found" }, 404);
    }

    if (request.method !== "POST") {
      return jsonResponse({ error: "method_not_allowed" }, 405, {
        Allow: "POST",
      });
    }

    if (!env.AUTH_LIMITER?.limit || !env.UPDATE_PASSWORD_HASH || !env.GITHUB_TOKEN) {
      console.error("Update service configuration is incomplete", {
        hasRateLimiter: Boolean(env.AUTH_LIMITER?.limit),
        hasPasswordHash: Boolean(env.UPDATE_PASSWORD_HASH),
        hasGitHubToken: Boolean(env.GITHUB_TOKEN),
      });
      return jsonResponse({ error: "service_unavailable" }, 503);
    }

    const contentType = request.headers.get("Content-Type") ?? "";
    if (contentType.split(";", 1)[0].trim().toLowerCase() !== "application/json") {
      return jsonResponse({ error: "invalid_request" }, 400);
    }

    let payload;
    try {
      const body = await readTextLimited(request.body, MAX_REQUEST_BYTES);
      if (body === null) {
        return jsonResponse({ error: "invalid_request" }, 400);
      }
      payload = JSON.parse(body);
    } catch {
      return jsonResponse({ error: "invalid_request" }, 400);
    }

    if (
      payload === null ||
      typeof payload !== "object" ||
      Array.isArray(payload) ||
      typeof payload.password !== "string" ||
      payload.password.length === 0 ||
      payload.password.length > 256
    ) {
      return jsonResponse({ error: "invalid_request" }, 400);
    }

    let rateLimit;
    try {
      rateLimit = await env.AUTH_LIMITER.limit({ key: await getRateLimitKey(request) });
    } catch {
      console.error("Update rate limiter check failed");
      return jsonResponse({ error: "service_unavailable" }, 503);
    }
    if (!rateLimit?.success) {
      return jsonResponse({ error: "too_many_requests" }, 429, {
        "Retry-After": "60",
      });
    }

    let authenticated;
    try {
      authenticated = await verifyPassword(payload.password, env.UPDATE_PASSWORD_HASH);
    } catch (error) {
      const reason = error instanceof Error ? error.name : "UnknownError";
      console.error("Update password verification failed", reason);
      return jsonResponse({ error: "service_unavailable" }, 503);
    }
    if (!authenticated) {
      return jsonResponse({ error: "unauthorized" }, 401);
    }

    try {
      return await downloadLatestApk(env);
    } catch (error) {
      const reason = error instanceof Error ? error.name : "UnknownError";
      console.error("Private update download failed", reason);
      return jsonResponse({ error: "upstream_unavailable" }, 502);
    }
  },
};

async function verifyPassword(password, encodedHash) {
  if (typeof encodedHash !== "string") {
    invalidPasswordHash("Missing");
  }

  const parts = encodedHash.split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2-sha256") {
    invalidPasswordHash("Format");
  }

  const iterations = Number(parts[1]);
  if (
    !Number.isInteger(iterations) ||
    iterations < MIN_PBKDF2_ITERATIONS ||
    iterations > MAX_PBKDF2_ITERATIONS
  ) {
    invalidPasswordHash("Iterations");
  }

  let salt;
  let expected;
  try {
    salt = decodeBase64(parts[2]);
    expected = decodeBase64(parts[3]);
  } catch {
    invalidPasswordHash("Encoding");
  }
  if (salt.length < 16 || expected.length !== 32) {
    invalidPasswordHash("Length");
  }

  const key = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const derived = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations },
      key,
      256,
    ),
  );
  return constantTimeEqual(derived, expected);
}

function invalidPasswordHash(reason) {
  const error = new Error("Invalid password hash configuration");
  error.name = `UpdatePasswordHash${reason}Error`;
  throw error;
}

function decodeBase64(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw new Error("Invalid password hash configuration");
  }
  const decoded = atob(value);
  return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
}

function constantTimeEqual(left, right) {
  if (left.length !== right.length) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

async function getRateLimitKey(request) {
  const address = request.headers.get("CF-Connecting-IP") || "unknown";
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", textEncoder.encode(address)),
  );
  const hex = Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `download:${hex}`;
}

async function downloadLatestApk(env) {
  const repository = env.GITHUB_REPOSITORY;
  const [owner, repo, ...extraParts] =
    typeof repository === "string" ? repository.split("/") : [];
  const assetName = env.GITHUB_ASSET_NAME;
  if (
    extraParts.length !== 0 ||
    !/^[A-Za-z0-9_.-]+$/.test(owner ?? "") ||
    !/^[A-Za-z0-9_.-]+$/.test(repo ?? "") ||
    typeof assetName !== "string" ||
    assetName.length === 0
  ) {
    throw diagnosticError("UpdateRepositoryConfigurationError");
  }

  const headers = {
    Accept: "application/vnd.github+json",
    "User-Agent": "UpdateGateway",
    Authorization: `Bearer ${env.GITHUB_TOKEN}`,
    "X-GitHub-Api-Version": "2022-11-28",
  };
  const releaseResponse = await withNetworkDiagnostic(
    "GitHubReleaseLookup",
    () => fetch(
      `https://api.github.com/repos/${owner}/${repo}/releases/latest`,
      { headers, redirect: "manual" },
    ),
  );
  if (!releaseResponse.ok) {
    throw await githubApiFailureDiagnostic(releaseResponse, "GitHubReleaseLookup");
  }

  const release = await readJsonLimited(releaseResponse, MAX_RELEASE_JSON_BYTES);
  if (!Array.isArray(release.assets)) {
    throw diagnosticError("GitHubReleaseAssetsInvalidError");
  }
  const asset = release.assets.find(
    (candidate) => candidate.name === assetName && candidate.state === "uploaded",
  );
  if (!asset || !Number.isSafeInteger(asset.id) || asset.id < 1) {
    throw diagnosticError("GitHubReleaseAssetMissingError");
  }

  const assetResponse = await withNetworkDiagnostic(
    "GitHubAssetRequest",
    () => fetch(
      `https://api.github.com/repos/${owner}/${repo}/releases/assets/${asset.id}`,
      {
        headers: {
          Accept: "application/octet-stream",
          "User-Agent": "UpdateGateway",
          Authorization: `Bearer ${env.GITHUB_TOKEN}`,
          "X-GitHub-Api-Version": "2022-11-28",
        },
        redirect: "manual",
      },
    ),
  );

  const binaryResponse = await followGitHubAssetRedirects(assetResponse);
  if (binaryResponse.status !== 200 || !binaryResponse.body) {
    throw diagnosticError(`GitHubAssetDownloadHTTP${binaryResponse.status}Error`);
  }

  const contentLength = binaryResponse.headers.get("Content-Length");
  if (contentLength !== null && (!/^\d+$/.test(contentLength) || Number(contentLength) > MAX_APK_BYTES)) {
    throw diagnosticError("GitHubAssetSizeInvalidError");
  }

  const responseHeaders = new Headers({
    "Cache-Control": "no-store",
    "Content-Disposition": 'attachment; filename="update.apk"',
    "Content-Type": "application/vnd.android.package-archive",
    "X-Content-Type-Options": "nosniff",
  });
  if (contentLength !== null) {
    responseHeaders.set("Content-Length", contentLength);
  }
  return new Response(capStream(binaryResponse.body, MAX_APK_BYTES), {
    status: 200,
    headers: responseHeaders,
  });
}

async function followGitHubAssetRedirects(response) {
  let current = response;
  for (let redirectCount = 0; redirectCount < 3; redirectCount += 1) {
    if (![301, 302, 303, 307, 308].includes(current.status)) {
      return current;
    }

    const location = current.headers.get("Location");
    if (!location) {
      throw diagnosticError("GitHubAssetRedirectLocationMissingError");
    }
    const target = new URL(location);
    if (target.protocol !== "https:" || !isGitHubAssetHost(target.hostname)) {
      throw diagnosticError("GitHubAssetRedirectTargetRejectedError");
    }
    current = await withNetworkDiagnostic(
      "GitHubAssetDownload",
      () => fetch(target, { redirect: "manual" }),
    );
  }
  throw diagnosticError("GitHubAssetRedirectLimitError");
}

function diagnosticError(name) {
  const error = new Error("Private update download failed");
  error.name = name;
  return error;
}

async function githubApiFailureDiagnostic(response, stage) {
  if (response.status !== 403) {
    return diagnosticError(`${stage}HTTP${response.status}Error`);
  }
  if (response.headers.get("X-RateLimit-Remaining") === "0") {
    return diagnosticError("GitHubRateLimitExceededError");
  }
  if ((response.headers.get("X-GitHub-SSO") ?? "").toLowerCase().includes("required")) {
    return diagnosticError("GitHubSSOAuthorizationRequiredError");
  }

  const body = await readTextLimited(response.body, MAX_GITHUB_ERROR_BYTES);
  if (body !== null) {
    let payload;
    try {
      payload = JSON.parse(body);
    } catch (error) {
      if (!(error instanceof SyntaxError)) {
        throw error;
      }
    }
    const message =
      payload && typeof payload.message === "string" ? payload.message.toLowerCase() : "";
    if (message.includes("rate limit")) {
      return diagnosticError("GitHubRateLimitExceededError");
    }
    if (message.includes("resource not accessible by personal access token")) {
      return diagnosticError("GitHubTokenPermissionDeniedError");
    }
    if (message.includes("user-agent") && message.includes("header")) {
      return diagnosticError("GitHubUserAgentRequiredError");
    }
    if (message.includes("saml") && message.includes("single sign-on")) {
      return diagnosticError("GitHubSSOAuthorizationRequiredError");
    }
  }
  return diagnosticError(`${stage}HTTP403Error`);
}

async function withNetworkDiagnostic(stage, request) {
  try {
    return await request();
  } catch (error) {
    if (error instanceof TypeError) {
      throw diagnosticError(`${stage}NetworkError`);
    }
    throw error;
  }
}

function isGitHubAssetHost(hostname) {
  return hostname === "githubusercontent.com" || hostname.endsWith(".githubusercontent.com");
}

async function readJsonLimited(response, limit) {
  const text = await readTextLimited(response.body, limit);
  if (text === null) {
    throw new Error("Upstream JSON response is too large");
  }
  return JSON.parse(text);
}

async function readTextLimited(stream, limit) {
  if (!stream) {
    return "";
  }
  const reader = stream.getReader();
  const chunks = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    length += value.byteLength;
    if (length > limit) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }

  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

function capStream(stream, limit) {
  const reader = stream.getReader();
  let length = 0;
  return new ReadableStream({
    async pull(controller) {
      try {
        const { done, value } = await reader.read();
        if (done) {
          controller.close();
          return;
        }
        length += value.byteLength;
        if (length > limit) {
          await reader.cancel();
          controller.error(new Error("APK exceeds the configured size limit"));
          return;
        }
        controller.enqueue(value);
      } catch {
        controller.error(new Error("APK stream failed"));
      }
    },
    cancel(reason) {
      return reader.cancel(reason);
    },
  });
}

function jsonResponse(body, status, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "application/json; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
      ...extraHeaders,
    },
  });
}
