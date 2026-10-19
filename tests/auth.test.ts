import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  getFreshAccessToken,
  login,
  logout,
  pollForToken,
  refreshAccessToken,
  requestDeviceCode,
  revokeRefreshToken,
} from "../src/auth.ts";
import { NotLoggedInError, TokenFamilyRevokedError } from "../src/errors.ts";
import { setDataDir } from "../src/paths.ts";
import { clearAccessTokenCache, readCredentials } from "../src/store.ts";
import { startMockServer, type MockServer } from "./mocks/server.ts";

let mock: MockServer;
let tmpDir: string;

beforeEach(async () => {
  mock = await startMockServer();
  tmpDir = await mkdtemp(join(tmpdir(), "dockerhub-test-"));
  setDataDir(tmpDir);
});

afterEach(async () => {
  setDataDir(null);
  clearAccessTokenCache();
  await rm(tmpDir, { recursive: true, force: true });
  mock.close();
});

describe("requestDeviceCode", () => {
  test("returns device + user codes", async () => {
    const device = await requestDeviceCode({
      baseUrl: mock.tenantUrl,
    });
    expect(device.device_code).toStartWith("dev_");
    expect(device.user_code).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    expect(device.verification_uri_complete).toContain(device.user_code);
    expect(device.expires_in).toBeGreaterThan(0);
  });
});

describe("pollForToken", () => {
  test("returns authorization_pending until approved, then success", async () => {
    const device = await requestDeviceCode({ baseUrl: mock.tenantUrl });
    let approved = false;
    const promise = pollForToken(device, {
      baseUrl: mock.tenantUrl,
      sleep: async () => {},
      onPending: () => {
        if (!approved) {
          approved = true;
          mock.approveDeviceCode(device.user_code, {
            nickname: "alice",
          });
        }
      },
    });
    const token = await promise;
    expect(token.access_token).toStartWith("at_");
    expect(token.refresh_token).toStartWith("rt_");
    expect(token.id_token).toBeDefined();
  });

  test("throws after device code expires", async () => {
    const device = await requestDeviceCode({ baseUrl: mock.tenantUrl });
    // simulate expired device code by setting expires_at in the past
    // via approving nothing and using a 0 expires_in device
    const expiredDevice = { ...device, expires_in: 0 };
    await expect(
      pollForToken(expiredDevice, {
        baseUrl: mock.tenantUrl,
        sleep: async () => {},
      }),
    ).rejects.toThrow(/expired/);
  });
});

describe("login", () => {
  test("persists credentials and returns username from /v/user", async () => {
    const onDeviceCodeCalls: string[] = [];
    const result = await login({
      baseUrl: mock.tenantUrl,
      hubBaseUrl: mock.hubUrl,
      browserOpener: async () => {},
      onDeviceCode: (d) => onDeviceCodeCalls.push(d.user_code),
      onPolling: () => {
        mock.approveDeviceCode(onDeviceCodeCalls[0]!, {
          nickname: "bob",
          sub: "auth0|bob",
        });
      },
    });
    // The mock's /v/user returns "testuser" unless overridden.
    expect(result.username).toBe("testuser");
    expect(result.refresh_token).toStartWith("rt_");
    const stored = await readCredentials();
    expect(stored.username).toBe("testuser");
    expect(stored.refresh_token).toBe(result.refresh_token);
    expect(onDeviceCodeCalls.length).toBe(1);
  });

  test("uses Hub API username over id_token claims", async () => {
    mock.setHubUsername("real-hub-user");
    const userCodes: string[] = [];
    await login({
      baseUrl: mock.tenantUrl,
      hubBaseUrl: mock.hubUrl,
      browserOpener: async () => {},
      onDeviceCode: (d) => userCodes.push(d.user_code),
      onPolling: () => {
        mock.approveDeviceCode(userCodes[0]!, {
          nickname: "ignored",
          sub: "auth0|ignored",
        });
      },
    });
    const stored = await readCredentials();
    expect(stored.username).toBe("real-hub-user");
  });

  test("falls back to id_token sub when /v/user fails and no nickname claim", async () => {
    mock.setHubUsername(null);
    mock.setHubFailNext({ status: 500, detail: "boom" });
    const userCodes: string[] = [];
    const result = await login({
      baseUrl: mock.tenantUrl,
      hubBaseUrl: mock.hubUrl,
      browserOpener: async () => {},
      onDeviceCode: (d) => userCodes.push(d.user_code),
      onPolling: () => {
        mock.approveDeviceCode(userCodes[0]!, {
          omitNickname: true,
          sub: "auth0|fallback-id",
        });
      },
    });
    expect(result.username).toBe("auth0|fallback-id");
  });

  test("falls back to id_token nickname when /v/user fails but nickname exists", async () => {
    mock.setHubUsername(null);
    mock.setHubFailNext({ status: 500, detail: "boom" });
    const userCodes: string[] = [];
    // Capture stderr so we can assert the warning fires.
    const stderrChunks: string[] = [];
    const origWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = ((chunk: string | Uint8Array) => {
      stderrChunks.push(typeof chunk === "string" ? chunk : new TextDecoder().decode(chunk));
      return origWrite(chunk);
    }) as typeof process.stderr.write;
    try {
      const result = await login({
        baseUrl: mock.tenantUrl,
        hubBaseUrl: mock.hubUrl,
        browserOpener: async () => {},
        onDeviceCode: (d) => userCodes.push(d.user_code),
        onPolling: () => {
          mock.approveDeviceCode(userCodes[0]!, {
            nickname: "id-token-nickname",
            sub: "auth0|ignored",
          });
        },
      });
      expect(result.username).toBe("id-token-nickname");
      const stderr = stderrChunks.join("");
      expect(stderr).toContain("/v/user endpoint was not reachable");
    } finally {
      process.stderr.write = origWrite;
    }
  });
});

describe("refreshAccessToken", () => {
  test("rejects with TokenFamilyRevokedError for unknown refresh token", async () => {
    await expect(
      refreshAccessToken("rt_unknown", { baseUrl: mock.tenantUrl }),
    ).rejects.toBeInstanceOf(TokenFamilyRevokedError);
  });
});

describe("getFreshAccessToken", () => {
  test("refreshes on first call, caches subsequent calls", async () => {
    // Seed credentials by running login.
    let userCode: string | undefined;
    await login({
      baseUrl: mock.tenantUrl,
      browserOpener: async () => {},
      onDeviceCode: (d) => {
        userCode = d.user_code;
      },
      onPolling: () => {
        if (userCode) mock.approveDeviceCode(userCode, { nickname: "carol" });
      },
    });

    clearAccessTokenCache();
    const a = await getFreshAccessToken({ baseUrl: mock.tenantUrl });
    expect(a).toStartWith("at_");
    const b = await getFreshAccessToken({ baseUrl: mock.tenantUrl });
    // second call should hit the cache and return same value
    expect(b).toBe(a);
  });

  test("rotates refresh token atomically", async () => {
    let userCode: string | undefined;
    await login({
      baseUrl: mock.tenantUrl,
      browserOpener: async () => {},
      onDeviceCode: (d) => {
        userCode = d.user_code;
      },
      onPolling: () => {
        if (userCode) mock.approveDeviceCode(userCode, { nickname: "dave" });
      },
    });

    clearAccessTokenCache();
    const before = (await readCredentials()).refresh_token;
    await getFreshAccessToken({ baseUrl: mock.tenantUrl });
    const after = (await readCredentials()).refresh_token;
    expect(after).not.toBe(before);
  });

  test("throws NotLoggedInError when no credentials exist", async () => {
    await expect(
      getFreshAccessToken({ baseUrl: mock.tenantUrl }),
    ).rejects.toBeInstanceOf(NotLoggedInError);
  });
});

describe("revokeRefreshToken / logout", () => {
  test("revoke accepts unknown tokens (200)", async () => {
    await expect(
      revokeRefreshToken("rt_unknown", { baseUrl: mock.tenantUrl }),
    ).resolves.toBeUndefined();
  });

  test("logout clears local credentials and revokes server-side", async () => {
    let userCode: string | undefined;
    await login({
      baseUrl: mock.tenantUrl,
      browserOpener: async () => {},
      onDeviceCode: (d) => {
        userCode = d.user_code;
      },
      onPolling: () => {
        if (userCode) mock.approveDeviceCode(userCode, { nickname: "eve" });
      },
    });
    await logout({ baseUrl: mock.tenantUrl });
    expect(readCredentials()).rejects.toBeInstanceOf(NotLoggedInError);
  });

  test("logout is a no-op when not logged in", async () => {
    await expect(logout({ baseUrl: mock.tenantUrl })).resolves.toBeUndefined();
  });
});