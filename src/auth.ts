/**
 * OAuth flows against login.docker.com (the Docker Auth0 tenant).
 *
 * Three flows are implemented:
 *   - device-code flow (RFC 8628) — `requestDeviceCode`, `pollForToken`, `login`
 *   - refresh-token grant (RFC 6749 §6) — `refreshAccessToken`, `getFreshAccessToken`
 *   - revoke (RFC 7009) — `revokeRefreshToken`, `logout`
 *
 * Single-flight and in-memory caching of the access token live here too,
 * so HubClient can ask for a fresh bearer token with one call.
 */

import { spawn } from "node:child_process";
import {
  CLIError,
  ExitCode,
  fromAuth0Error,
  NotLoggedInError,
} from "./errors.ts";
import { decodeIdToken } from "./jwt.ts";
import {
  parseDeviceCodeResponse,
  parseOAuthErrorBody,
  parseTokenResponse,
} from "./shapes.ts";
import {
  clearAccessTokenCache,
  deleteCredentials,
  getAccessTokenCache,
  isAccessTokenFresh,
  readCredentials,
  setAccessTokenCache,
  withFileLock,
  writeCredentials,
} from "./store.ts";
import type {
  BrowserOpener,
  DeviceCodeResponse,
  TokenResponse,
} from "./types.ts";
import {
  AUTH0_AUDIENCE,
  DOCKERHUB_CLIENT_ID,
  LOGIN_SCOPES,
  TENANT_BASE_URL,
} from "./types.ts";
import { HubClient } from "./hub.ts";

// ----- Default browser opener -----

/**
 * Open the user's default browser at `url`. Never throws — if the
 * platform opener command is unavailable the caller should print the
 * URL for the user to copy.
 */
export async function defaultBrowserOpener(url: string): Promise<void> {
  let cmd: string;
  let args: string[];
  if (process.platform === "darwin") {
    cmd = "open";
    args = [url];
  } else if (process.platform === "win32") {
    cmd = "cmd";
    args = ["/c", "start", "", url];
  } else {
    cmd = "xdg-open";
    args = [url];
  }
  try {
    const child = spawn(cmd, args, {
      stdio: "ignore",
      detached: true,
    });
    child.unref();
  } catch {
    // ignore — caller is expected to print the URL
  }
}

// ----- Device-code flow -----

export async function requestDeviceCode(
  opts: { baseUrl?: string; fetchImpl?: typeof fetch } = {},
): Promise<DeviceCodeResponse> {
  const baseUrl = opts.baseUrl ?? TENANT_BASE_URL;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const body = new URLSearchParams({
    client_id: DOCKERHUB_CLIENT_ID,
    audience: AUTH0_AUDIENCE,
    scope: LOGIN_SCOPES.join(" "),
  });
  const res = await fetchImpl(`${baseUrl}/oauth/device/code`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new CLIError(
      `Device code request failed: HTTP ${res.status}`,
      {
        exitCode: ExitCode.Unavailable,
        hint: "Check network connectivity to login.docker.com.",
        detail: text.slice(0, 200),
      },
    );
  }
  return parseDeviceCodeResponse(await res.json());
}

export interface PollOptions {
  baseUrl?: string;
  fetchImpl?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  onPending?: (attempt: number, secondsRemaining: number) => void;
  now?: () => number;
}

/**
 * Poll the token endpoint until authorization succeeds, the device
 * code expires, or the user denies access. Honors the device-code
 * response `interval` field and Auth0's `slow_down` error.
 */
export async function pollForToken(
  device: DeviceCodeResponse,
  opts: PollOptions = {},
): Promise<TokenResponse> {
  const baseUrl = opts.baseUrl ?? TENANT_BASE_URL;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const sleep = opts.sleep ?? defaultSleep;
  const now = opts.now ?? Date.now;
  const deadline = now() + device.expires_in * 1000;
  let interval = device.interval;
  let attempt = 0;
  while (true) {
    attempt++;
    if (now() >= deadline) {
      throw new CLIError(
        "Device code expired before authorization.",
        {
          exitCode: ExitCode.GeneralError,
          hint: "Re-run `dockerhub login` and complete the browser step within 15 minutes.",
        },
      );
    }
    const body = new URLSearchParams({
      client_id: DOCKERHUB_CLIENT_ID,
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      device_code: device.device_code,
    });
    const res = await fetchImpl(`${baseUrl}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
    const json = await res.json();
    if (res.ok) {
      return parseTokenResponse(json);
    }
    const errBody = parseOAuthErrorBody(json);
    switch (errBody.error) {
      case "authorization_pending":
        opts.onPending?.(
          attempt,
          Math.max(0, Math.floor((deadline - now()) / 1000)),
        );
        await sleep(interval * 1000);
        continue;
      case "slow_down":
        interval += 5;
        await sleep(interval * 1000);
        continue;
      default:
        throw fromAuth0Error(errBody, res.status);
    }
  }
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// ----- Login orchestration -----

export interface LoginOptions {
  fetchImpl?: typeof fetch;
  browserOpener?: BrowserOpener;
  baseUrl?: string;
  hubBaseUrl?: string;
  onDeviceCode?: (device: DeviceCodeResponse) => void;
  onPolling?: (attempt: number, secondsRemaining: number) => void;
}

export interface LoginResult {
  username: string;
  refresh_token: string;
}

export async function login(opts: LoginOptions = {}): Promise<LoginResult> {
  const opener = opts.browserOpener ?? defaultBrowserOpener;
  const device = await requestDeviceCode({
    baseUrl: opts.baseUrl,
    fetchImpl: opts.fetchImpl,
  });
  opts.onDeviceCode?.(device);
  await opener(device.verification_uri_complete);
  const token = await pollForToken(device, {
    baseUrl: opts.baseUrl,
    fetchImpl: opts.fetchImpl,
    onPending: opts.onPolling,
  });
  if (!token.refresh_token) {
    throw new CLIError(
      "OAuth response missing refresh_token.",
      {
        exitCode: ExitCode.HubError,
        hint: "Auth0 must issue a refresh_token. Check the tenant configuration.",
      },
    );
  }

  // Resolve the canonical Docker Hub username. Priority:
  //   1. GET /v2/user with the new access token (canonical, always correct)
  //   2. id_token.nickname (sometimes present, often missing for social logins)
  //   3. id_token.name (sometimes present)
  //   4. id_token.sub — opaque Auth0 id like `auth0|<uuid>`. Last resort, with warning.
  let resolvedUsername: string | undefined;
  let usernameSource: "db" | "id_token" | "fallback" | undefined;
  try {
    const hub = new HubClient({
      baseUrl: opts.hubBaseUrl,
      fetchImpl: opts.fetchImpl,
      getAccessToken: async () => token.access_token,
    });
    const { username } = await hub.getCurrentUser();
    resolvedUsername = username;
    usernameSource = "db";
  } catch (err) {
    // Hub call failed (network blip, transient 5xx, or a 401 if the
    // access token has somehow expired before we used it). We still
    // fall back to the id_token so the user can complete login, but
    // surface what happened — without the warning, the user stores an
    // opaque `auth0|<uuid>` and wonders why their CLI greets them as
    // a uuid instead of their username.
    process.stderr.write(
      `\nNote: Docker Hub's /v/user endpoint was not reachable ` +
        `(${(err as Error).message}). Falling back to id_token claims.\n`,
    );
  }
  if (!resolvedUsername && token.id_token) {
    try {
      const claims = decodeIdToken(token.id_token);
      resolvedUsername = claims.nickname ?? claims.name;
      if (resolvedUsername) usernameSource = "id_token";
    } catch {
      // fall through
    }
  }
  if (!resolvedUsername && token.id_token) {
    try {
      const claims = decodeIdToken(token.id_token);
      resolvedUsername = claims.sub;
      usernameSource = "fallback";
    } catch {
      // fall through
    }
  }
  if (!resolvedUsername) {
    throw new CLIError(
      "Could not determine username.",
      {
        exitCode: ExitCode.HubError,
        hint: "Hub's /v2/user returned no username, and the id_token had no usable claims.",
      },
    );
  }

  if (usernameSource === "fallback") {
    process.stderr.write(
      `\nWarning: could not reach the Hub to fetch your username. Stored an opaque id (` +
        `${resolvedUsername}) instead. Run \`dockerhub logout\` then \`dockerhub login\` ` +
        `to retry.\n`,
    );
  }

  const creds = {
    version: 1 as const,
    refresh_token: token.refresh_token,
    username: resolvedUsername,
    saved_at: new Date().toISOString(),
    scopes: [...LOGIN_SCOPES],
    client_id: DOCKERHUB_CLIENT_ID,
  };
  await writeCredentials(creds);
  clearAccessTokenCache();
  return {
    username: resolvedUsername,
    refresh_token: token.refresh_token,
  };
}

// ----- Refresh-token grant -----

export async function refreshAccessToken(
  refreshToken: string,
  opts: { baseUrl?: string; fetchImpl?: typeof fetch } = {},
): Promise<TokenResponse> {
  const baseUrl = opts.baseUrl ?? TENANT_BASE_URL;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const body = new URLSearchParams({
    client_id: DOCKERHUB_CLIENT_ID,
    grant_type: "refresh_token",
    refresh_token: refreshToken,
  });
  const res = await fetchImpl(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  const json = await res.json();
  if (!res.ok) {
    throw fromAuth0Error(parseOAuthErrorBody(json), res.status);
  }
  return parseTokenResponse(json);
}

export interface GetAccessTokenOptions {
  fetchImpl?: typeof fetch;
  baseUrl?: string;
  now?: () => number;
}

/**
 * Returns a fresh access token. Uses an in-process cache and
 * single-flight locking so concurrent calls do not both rotate the
 * refresh token (which would trigger Auth0 reuse detection).
 */
export async function getFreshAccessToken(
  opts: GetAccessTokenOptions = {},
): Promise<string> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const now = opts.now ?? Date.now;
  const cached = getAccessTokenCache();
  if (cached && isAccessTokenFresh(cached, 60_000, now())) {
    return cached.access_token;
  }
  return await withFileLock(async () => {
    // Re-read inside the lock — another process may have just refreshed.
    const creds = await readCredentials();
    const stillCached = getAccessTokenCache();
    if (stillCached && isAccessTokenFresh(stillCached, 60_000, now())) {
      return stillCached.access_token;
    }
    const token = await refreshAccessToken(creds.refresh_token, {
      fetchImpl,
      baseUrl: opts.baseUrl,
    });
    const expiresAt = now() + token.expires_in * 1000;
    setAccessTokenCache({
      access_token: token.access_token,
      expires_at: expiresAt,
    });
    if (
      token.refresh_token &&
      token.refresh_token !== creds.refresh_token
    ) {
      await writeCredentials({
        ...creds,
        refresh_token: token.refresh_token,
        saved_at: new Date().toISOString(),
      });
    }
    return token.access_token;
  });
}

// ----- Revoke (logout) -----

export async function revokeRefreshToken(
  refreshToken: string,
  opts: { baseUrl?: string; fetchImpl?: typeof fetch } = {},
): Promise<void> {
  const baseUrl = opts.baseUrl ?? TENANT_BASE_URL;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const body = new URLSearchParams({
    client_id: DOCKERHUB_CLIENT_ID,
    token: refreshToken,
  });
  const res = await fetchImpl(`${baseUrl}/oauth/revoke`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  if (res.ok) return;
  // Tolerate 400/403 — Auth0 returns them for already-revoked tokens.
  let detail = `HTTP ${res.status}`;
  try {
    const json = (await res.json()) as {
      error?: string;
      error_description?: string;
    };
    detail = json.error_description ?? json.error ?? detail;
  } catch {
    // ignore
  }
  process.stderr.write(
    `Warning: server-side revoke returned ${detail}. Local credentials still cleared.\n`,
  );
}

export async function logout(
  opts: { fetchImpl?: typeof fetch; baseUrl?: string } = {},
): Promise<void> {
  try {
    const creds = await readCredentials();
    await revokeRefreshToken(creds.refresh_token, {
      fetchImpl: opts.fetchImpl,
      baseUrl: opts.baseUrl,
    });
  } catch (err) {
    if (!(err instanceof NotLoggedInError)) {
      process.stderr.write(
        `Warning: could not read stored credentials: ${(err as Error).message}\n`,
      );
    }
  }
  await deleteCredentials();
  clearAccessTokenCache();
}