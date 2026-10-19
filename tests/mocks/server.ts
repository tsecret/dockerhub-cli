/**
 * Mock HTTP server that emulates login.docker.com and hub.docker.com
 * for tests. Lets test code drive state changes (approve device
 * codes, rotate refresh tokens, etc.) so we can exercise the full
 * auth + Hub flow without real network calls or secrets.
 *
 * Usage:
 *   const mock = await startMockServer();
 *   // pass mock.eventHubsUrl and mock.tenantUrl into the modules under test
 *   mock.approveDeviceCode("ABCD-EFGH");
 *   mock.close();
 */

import {
  AUTH0_AUDIENCE,
  DOCKERHUB_CLIENT_ID,
  LOGIN_SCOPES,
  TENANT_BASE_URL,
  type HubPAT,
} from "../../src/types.ts";

interface DeviceCodeEntry {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  expires_at: number;
  expires_in: number;
  interval: number;
  approved: boolean;
  sub: string;
  nickname: string;
  omitNickname: boolean;
}

interface RefreshTokenEntry {
  refresh_token: string;
  family_id: string;
  /** Set to the successor's refresh_token when rotation invalidates this one. */
  superseded_by?: string;
  access_token: string;
  id_token: string;
  expires_in: number;
  revoked: boolean;
  rotate: boolean;
}

export interface MockServer {
  tenantUrl: string;
  hubUrl: string;
  /** Approve a device code so the next token poll succeeds. */
  approveDeviceCode: (
    userCode: string,
    profile?: {
      sub?: string;
      nickname?: string;
      /** When true, the issued id_token omits the nickname claim entirely. */
      omitNickname?: boolean;
    },
  ) => void;
  /** Toggle whether refresh grants rotate. Default: true. */
  setRefreshRotation: (enabled: boolean) => void;
  /** Revoke every refresh token (simulates Auth0 family revocation). */
  revokeAllFamilies: () => void;
  /** Seed a PAT in the Hub so list/inspect return it. */
  addPreExistingPAT: (partial?: Partial<HubPAT>) => HubPAT;
  /** Force the next Hub response to fail. */
  setHubFailNext: (fail: { status: number; detail?: string } | null) => void;
  /** Override the canonical username returned by /v2/user. */
  setHubUsername: (username: string | null) => void;
  close: () => void;
}

export async function startMockServer(): Promise<MockServer> {
  const devices = new Map<string, DeviceCodeEntry>();
  const userCodes = new Map<string, string>();
  const refreshTokens = new Map<string, RefreshTokenEntry>();
  const pats = new Map<string, HubPAT>();
  let rotate = true;
  let nextFail: { status: number; detail?: string } | null = null;
  let overrideUsername: string | null = null;

  const tenant = Bun.serve({
    port: 0,
    async fetch(req: Request): Promise<Response> {
      const url = new URL(req.url);
      if (req.method === "POST" && url.pathname === "/oauth/device/code") {
        const body = await req.formData();
        if (body.get("client_id") !== DOCKERHUB_CLIENT_ID) {
          return json({ error: "invalid_client" }, 401);
        }
        if (body.get("audience") !== AUTH0_AUDIENCE) {
          return json(
            { error: "invalid_request", error_description: "audience mismatch" },
            400,
          );
        }
        const deviceCode = `dev_${Math.random().toString(36).slice(2)}`;
        const userCode = `${randomChars(4)}-${randomChars(4)}`.toUpperCase();
        const entry: DeviceCodeEntry = {
          device_code: deviceCode,
          user_code: userCode,
          verification_uri: `${TENANT_BASE_URL}/activate`,
          verification_uri_complete: `${TENANT_BASE_URL}/activate?user_code=${userCode}`,
          expires_at: Date.now() + 900_000,
          expires_in: 900,
          interval: 1,
          approved: false,
          sub: "auth0|user",
          nickname: "testuser",
          omitNickname: false,
        };
        devices.set(deviceCode, entry);
        userCodes.set(userCode, deviceCode);
        return json(entry, 200);
      }

      if (req.method === "POST" && url.pathname === "/oauth/token") {
        const body = await req.formData();
        const grant = body.get("grant_type");

        if (grant === "urn:ietf:params:oauth:grant-type:device_code") {
          const deviceCode = body.get("device_code") as string;
          const entry = devices.get(deviceCode);
          if (!entry) return json({ error: "invalid_grant" }, 403);
          if (Date.now() > entry.expires_at) {
            return json({ error: "expired_token" }, 403);
          }
          if (!entry.approved) {
            return json({ error: "authorization_pending" }, 403);
          }
          const refresh = `rt_${randomChars(16)}`;
          const access = `at_${randomChars(24)}`;
          const id = makeFakeIdToken(
            entry.sub,
            entry.omitNickname ? "" : entry.nickname,
            entry.omitNickname ?? false,
          );
          const familyId = `fam_${randomChars(8)}`;
          const rtEntry: RefreshTokenEntry = {
            refresh_token: refresh,
            family_id: familyId,
            access_token: access,
            id_token: id,
            expires_in: 900,
            revoked: false,
            rotate,
          };
          refreshTokens.set(refresh, rtEntry);
          return json(
            {
              access_token: access,
              id_token: id,
              refresh_token: refresh,
              expires_in: 900,
              token_type: "Bearer",
              scope: LOGIN_SCOPES.join(" "),
            },
            200,
          );
        }

        if (grant === "refresh_token") {
          const rt = body.get("refresh_token") as string;
          const rtRec = refreshTokens.get(rt);
          if (!rtRec || rtRec.revoked) {
            return json({ error: "invalid_grant" }, 403);
          }
          // Reuse detection: token was already rotated.
          if (rtRec.superseded_by !== undefined) {
            // Revoke entire family.
            for (const e of refreshTokens.values()) {
              if (e.family_id === rtRec.family_id) e.revoked = true;
            }
            return json({ error: "invalid_grant" }, 403);
          }
          const newAccess = `at_${randomChars(24)}`;
          let newRefresh = rt;
          if (rtRec.rotate) {
            newRefresh = `rt_${randomChars(16)}`;
            rtRec.superseded_by = newRefresh;
            const newRtEntry: RefreshTokenEntry = {
              refresh_token: newRefresh,
              family_id: rtRec.family_id,
              access_token: newAccess,
              id_token: rtRec.id_token,
              expires_in: 900,
              revoked: false,
              rotate: rtRec.rotate,
            };
            refreshTokens.set(newRefresh, newRtEntry);
          }
          return json(
            {
              access_token: newAccess,
              id_token: rtRec.id_token,
              refresh_token: newRefresh,
              expires_in: 900,
              token_type: "Bearer",
              scope: LOGIN_SCOPES.join(" "),
            },
            200,
          );
        }

        return json({ error: "unsupported_grant_type" }, 400);
      }

      if (req.method === "POST" && url.pathname === "/oauth/revoke") {
        const body = await req.formData();
        const token = body.get("token") as string;
        const entry = refreshTokens.get(token);
        if (entry) entry.revoked = true;
        return new Response(null, { status: 200 });
      }

      return json({ error: "not_found" }, 404);
    },
  });

  const hub = Bun.serve({
    port: 0,
    async fetch(req: Request): Promise<Response> {
      const url = new URL(req.url);
      const auth = req.headers.get("Authorization") ?? "";
      const match = /^Bearer (.+)$/.exec(auth);
      if (!match) {
        return json({ detail: "Missing Authorization header" }, 401);
      }
      const token = match[1] as string;
      if (!token.startsWith("at_")) {
        return json({ detail: "Invalid token" }, 401);
      }

      if (nextFail) {
        const fail = nextFail;
        nextFail = null;
        return json({ detail: fail.detail ?? "Forced failure" }, fail.status);
      }

      if (req.method === "GET" && url.pathname === "/v2/user") {
        const username = overrideUsername ?? "testuser";
        return json({ user: { username, email: `${username}@example.com` } }, 200);
      }

      if (req.method === "GET" && url.pathname === "/v2/access-tokens") {
        const list = Array.from(pats.values()).map((p) => ({
          ...p,
          token: "***",
        }));
        return json(
          {
            results: list,
            active_count: list.filter((p) => p.is_active).length,
            count: list.length,
            next: null,
            previous: null,
          },
          200,
        );
      }

      const inspectMatch = /^\/v2\/access-tokens\/([^/]+)$/.exec(url.pathname);
      if (req.method === "GET" && inspectMatch) {
        const uuid = inspectMatch[1] as string;
        const pat = pats.get(uuid);
        if (!pat) return json({ detail: "Not found" }, 404);
        return json({ ...pat, token: "***" }, 200);
      }

      if (req.method === "POST" && url.pathname === "/v2/access-tokens") {
        const body = (await req.json()) as {
          token_label: string;
          scopes: string[];
          expires_at?: string;
        };
        const uuid = crypto.randomUUID();
        const token = `dckr_pat_${randomChars(24)}`;
        const entry: HubPAT = {
          uuid,
          client_id: "HUB",
          creator_ip: "127.0.0.1",
          creator_ua: "dockerhub-cli/test",
          created_at: new Date().toISOString(),
          last_used: null,
          generated_by: "manual",
          is_active: true,
          token,
          token_label: body.token_label,
          scopes: body.scopes,
          expires_at: body.expires_at ?? null,
        };
        pats.set(uuid, entry);
        return json(entry, 201);
      }

      if (req.method === "DELETE" && inspectMatch) {
        const uuid = inspectMatch[1] as string;
        const pat = pats.get(uuid);
        if (!pat) return json({ detail: "Not found" }, 404);
        pats.delete(uuid);
        return new Response(null, { status: 204 });
      }

      return json({ detail: "Not found" }, 404);
    },
  });

  return {
    tenantUrl: `http://localhost:${tenant.port}`,
    hubUrl: `http://localhost:${hub.port}`,
    approveDeviceCode: (
      userCode: string,
      profile: {
        sub?: string;
        nickname?: string;
        omitNickname?: boolean;
      } = {},
    ) => {
      const deviceCode = userCodes.get(userCode);
      if (!deviceCode) throw new Error(`Unknown user_code: ${userCode}`);
      const entry = devices.get(deviceCode);
      if (!entry) throw new Error(`No device entry for ${deviceCode}`);
      entry.approved = true;
      if (profile.sub) entry.sub = profile.sub;
      if (profile.nickname) entry.nickname = profile.nickname;
      entry.omitNickname = profile.omitNickname ?? false;
    },
    setRefreshRotation: (enabled: boolean) => {
      rotate = enabled;
    },
    revokeAllFamilies: () => {
      for (const e of refreshTokens.values()) e.revoked = true;
    },
    addPreExistingPAT: (partial: Partial<HubPAT> = {}) => {
      const uuid = partial.uuid ?? crypto.randomUUID();
      const entry: HubPAT = {
        uuid,
        client_id: partial.client_id ?? "HUB",
        creator_ip: partial.creator_ip ?? "127.0.0.1",
        creator_ua: partial.creator_ua ?? "dockerhub-cli/test",
        created_at: partial.created_at ?? new Date().toISOString(),
        last_used: partial.last_used ?? null,
        generated_by: partial.generated_by ?? "manual",
        is_active: partial.is_active ?? true,
        token: partial.token ?? `dckr_pat_${randomChars(24)}`,
        token_label: partial.token_label ?? "pre-existing",
        scopes: partial.scopes ?? ["repo:read"],
        expires_at: partial.expires_at ?? null,
      };
      pats.set(uuid, entry);
      return entry;
    },
    setHubFailNext: (fail) => {
      nextFail = fail;
    },
    setHubUsername: (username) => {
      overrideUsername = username;
    },
    close: () => {
      tenant.stop(true);
      hub.stop(true);
    },
  };
}

function json(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function randomChars(n: number): string {
  return Math.random().toString(36).slice(2, 2 + n);
}

function makeFakeIdToken(
  sub: string,
  nickname: string,
  omitNickname = false,
): string {
  const header = btoa(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claims: Record<string, unknown> = {
    sub,
    iss: TENANT_BASE_URL + "/",
    aud: AUTH0_AUDIENCE,
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
  };
  if (!omitNickname) {
    claims.nickname = nickname;
    claims.name = nickname;
    claims.email = `${nickname}@example.com`;
  }
  const payload = btoa(JSON.stringify(claims));
  const sig = "fake-signature";
  return `${header}.${payload}.${sig}`;
}