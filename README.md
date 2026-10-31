# Update Gateway

This repository is intended to hold the public update manifest and the Cloudflare Worker source. Never commit APKs, GitHub tokens, password hashes, or the shared password here.

The client app will read the public manifest from:

`https://raw.githubusercontent.com/famin-dotcom/M-G-Update/main/update.json`

The current `update.json` advertises the tested versionCode 363 release. For each future update, publish the matching signed APK to the private APK repository and deploy the Worker before changing the active manifest. The Worker serves `POST /download`; the app verifies the returned APK against the manifest SHA-256 before opening Android's installer.

## Worker setup

1. Install Node.js 20 or newer, then run `npm install` and `npm test`.
2. In `wrangler.toml`, choose a `namespace_id` that is an unused integer in your Cloudflare account. The rate-limit binding allows five download attempts per minute per source IP and Cloudflare location. It also counts successful attempts, and Cloudflare's binding is not a globally consistent counter.
3. Authenticate Wrangler with `npx wrangler login`.
4. Create a fine-grained GitHub token limited to the private APK repository with read-only Contents access. Store it as a Worker secret:

   ```powershell
   npx wrangler secret put GITHUB_TOKEN
   ```

5. Store the private repository identifier as `owner/repo` in a Worker secret:

   ```powershell
   npx wrangler secret put GITHUB_REPOSITORY
   ```

6. Store the exact private release asset filename as a secret:

   ```powershell
   npx wrangler secret put GITHUB_ASSET_NAME
   ```

7. Generate a salted PBKDF2-SHA256 verifier with the hidden-input PowerShell script, then paste its output into Wrangler's secret prompt:

   ```powershell
   $verifier = & .\scripts\New-UpdatePasswordHash.ps1
   $parts = $verifier.Split('$')
   if ($parts.Count -ne 4 -or $parts[0] -ne 'pbkdf2-sha256' -or $parts[1] -ne '100000') {
       throw 'Generated verifier format is invalid.'
   }
   $verifier | npx wrangler secret put UPDATE_PASSWORD_HASH
   ```

   The password must be at least 16 characters. The script prints only the verifier; it never writes the password to a file. Piping the verifier to Wrangler avoids displaying or manually copying it. Do not put passwords, hashes, or tokens in this repository or the client app.

   The verifier uses 100,000 PBKDF2 iterations to stay within the Cloudflare Workers Free runtime limit.

8. Publish the private GitHub release containing the signed APK, then deploy:

   ```powershell
   npx wrangler deploy
   ```

9. Record the deployed `/download` URL in the client configuration. The raw manifest URL above is the client's `MANIFEST_URL`. Rebuild and sign the app with the existing signing certificate before testing.

Worker Logs and invocation logs are enabled at 100% in `wrangler.toml` so deployments preserve the diagnostic configuration. The dashboard currently displays the Free-plan allowance of 200,000 events per day; events beyond the limit are sampled.

Inspect Worker Logs for safe configuration, rate-limiter, password-verifier, and GitHub upstream failure categories. GitHub API requests include a static `User-Agent`. GitHub 403 responses are classified using only safe status/header values and a bounded response message match (rate limit, token permission, SSO, or User-Agent policy); raw response bodies and credentials are never logged.

## Manifest format

The public `update.json` contains only non-sensitive metadata:

```json
{
  "versionCode": 363,
  "stop": 0,
  "updateInfo": "Release notes",
  "sha256": "64-character-hex-sha256-of-the-signed-apk"
}
```

Set `versionCode` to the signed APK's actual version code and calculate SHA-256 after signing. The manifest must match the APK served by the latest private release. Do not publish a manifest until both are ready.
