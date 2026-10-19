import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  NotLoggedInError,
  StorageError,
} from "../src/errors.ts";
import { setDataDir } from "../src/paths.ts";
import {
  clearAccessTokenCache,
  credentialsExist,
  deleteCredentials,
  ensureDataDir,
  getAccessTokenCache,
  isAccessTokenFresh,
  readCredentials,
  setAccessTokenCache,
  withFileLock,
  writeCredentials,
} from "../src/store.ts";
import { DOCKERHUB_CLIENT_ID } from "../src/types.ts";

let tmpDir: string;

beforeEach(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), "dockerhub-test-"));
  setDataDir(tmpDir);
});

afterEach(async () => {
  setDataDir(null);
  clearAccessTokenCache();
  await rm(tmpDir, { recursive: true, force: true });
});

const fakeCreds = (overrides = {}) => ({
  version: 1 as const,
  refresh_token: "rt_test",
  username: "alice",
  saved_at: "2026-10-19T00:00:00.000Z",
  scopes: ["openid", "offline_access"],
  client_id: DOCKERHUB_CLIENT_ID,
  ...overrides,
});

describe("ensureDataDir", () => {
  test("creates the data directory", async () => {
    await ensureDataDir();
    const s = await stat(tmpDir);
    expect(s.isDirectory()).toBe(true);
  });

  test("is idempotent", async () => {
    await ensureDataDir();
    await ensureDataDir();
    // no throw
  });
});

describe("writeCredentials / readCredentials", () => {
  test("round-trips", async () => {
    await writeCredentials(fakeCreds());
    const got = await readCredentials();
    expect(got.username).toBe("alice");
    expect(got.refresh_token).toBe("rt_test");
  });

  test("sets file mode to 0600", async () => {
    await writeCredentials(fakeCreds());
    const s = await stat(join(tmpDir, "auth.json"));
    // mask out type bits
    expect(s.mode & 0o777).toBe(0o600);
  });

  test("readCredentials throws NotLoggedInError when file missing", async () => {
    expect(readCredentials()).rejects.toBeInstanceOf(NotLoggedInError);
  });

  test("readCredentials throws StorageError on corrupted JSON", async () => {
    await Bun.write(join(tmpDir, "auth.json"), "not json");
    expect(readCredentials()).rejects.toBeInstanceOf(StorageError);
  });

  test("readCredentials throws NotLoggedInError on client_id mismatch", async () => {
    await writeCredentials(fakeCreds({ client_id: "different-client" }));
    expect(readCredentials()).rejects.toBeInstanceOf(NotLoggedInError);
  });

  test("readCredentials throws StorageError on version mismatch", async () => {
    await Bun.write(
      join(tmpDir, "auth.json"),
      JSON.stringify({ version: 99, refresh_token: "x" }),
    );
    expect(readCredentials()).rejects.toBeInstanceOf(StorageError);
  });
});

describe("deleteCredentials", () => {
  test("removes the file", async () => {
    await writeCredentials(fakeCreds());
    expect(await credentialsExist()).toBe(true);
    await deleteCredentials();
    expect(await credentialsExist()).toBe(false);
  });

  test("is idempotent when missing", async () => {
    await deleteCredentials();
    await deleteCredentials();
  });
});

describe("withFileLock", () => {
  test("runs the function under lock", async () => {
    let observed = false;
    await withFileLock(async () => {
      observed = true;
    });
    expect(observed).toBe(true);
  });

  test("serializes concurrent callers", async () => {
    // Two concurrent acquisitions must not run at the same time.
    // We track a counter; if the lock works, the counter never exceeds 2
    // (one increment + one decrement) and always returns to its starting
    // value at the end. If the lock is broken, both inner functions run
    // concurrently and the counter hits 2.
    let inFlight = 0;
    let maxInFlight = 0;
    const make = () =>
      withFileLock(async () => {
        inFlight++;
        maxInFlight = Math.max(maxInFlight, inFlight);
        await new Promise((r) => setTimeout(r, 30));
        inFlight--;
      });
    await Promise.all([make(), make(), make()]);
    expect(maxInFlight).toBe(1);
    expect(inFlight).toBe(0);
  });

  test("releases lock on throw", async () => {
    await expect(
      withFileLock(async () => {
        throw new Error("boom");
      }),
    ).rejects.toThrow("boom");
    // lock should be released — second acquire should succeed
    await withFileLock(async () => {});
  });
});

describe("access-token cache", () => {
  test("isAccessTokenFresh respects skew", () => {
    setAccessTokenCache({ access_token: "x", expires_at: 1000 });
    expect(isAccessTokenFresh({ access_token: "x", expires_at: 1000 }, 60, 500)).toBe(true);
    expect(isAccessTokenFresh({ access_token: "x", expires_at: 1000 }, 60, 950)).toBe(false);
  });

  test("get/set/clear", () => {
    expect(getAccessTokenCache()).toBeNull();
    setAccessTokenCache({ access_token: "x", expires_at: 100 });
    expect(getAccessTokenCache()?.access_token).toBe("x");
    clearAccessTokenCache();
    expect(getAccessTokenCache()).toBeNull();
  });
});