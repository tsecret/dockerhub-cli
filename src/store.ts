/**
 * Persistent storage layer.
 *
 * Three concerns:
 *  1. Atomic write of the auth file (mode 0600) so a crash mid-write
 *     can never leave a half-written file. See ADR-0002.
 *  2. Single-flight locking so concurrent CLI invocations do not
 *     both refresh the same OAuth token family (which would trigger
 *     Auth0 reuse detection and force re-login). See ADR-0003.
 *  3. In-memory access-token cache held for the lifetime of one CLI
 *     invocation, refreshed on demand.
 */

import {
  chmod,
  mkdir,
  open,
  readFile,
  rename,
  stat,
  unlink,
  writeFile,
} from "node:fs/promises";
import {
  NotLoggedInError,
  StorageError,
} from "./errors.ts";
import { getAuthFilePath, getDataDir, getLockFilePath } from "./paths.ts";
import {
  DOCKERHUB_CLIENT_ID,
  type AccessTokenCache,
  type StoredCredentials,
} from "./types.ts";

const AUTH_FILE_VERSION = 1 as const;
const AUTH_FILE_MODE = 0o600;
const DATA_DIR_MODE = 0o700;
const LOCK_RETRY_MS = 100;
const LOCK_TIMEOUT_MS = 10_000;
const ACCESS_TOKEN_SKEW_MS = 60_000;

/** Ensure the data directory exists with mode 0700. */
export async function ensureDataDir(): Promise<void> {
  await mkdir(getDataDir(), { recursive: true, mode: DATA_DIR_MODE });
}

/**
 * Read credentials from disk. Throws NotLoggedInError if absent or
 * if the file was written by a different OAuth client_id (the Hub may
 * have rotated; in that case the refresh token is unusable).
 */
export async function readCredentials(): Promise<StoredCredentials> {
  let raw: string;
  try {
    raw = await readFile(getAuthFilePath(), "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      throw new NotLoggedInError();
    }
    throw new StorageError(
      `Could not read auth file: ${(err as Error).message}`,
      err,
    );
  }
  let parsed: StoredCredentials;
  try {
    parsed = JSON.parse(raw) as StoredCredentials;
  } catch (err) {
    throw new StorageError(
      `Auth file is corrupted (invalid JSON): ${(err as Error).message}`,
      err,
    );
  }
  if (parsed.version !== AUTH_FILE_VERSION) {
    throw new StorageError(
      `Unsupported auth file version: ${parsed.version}. Expected ${AUTH_FILE_VERSION}.`,
    );
  }
  if (parsed.client_id !== DOCKERHUB_CLIENT_ID) {
    // The OAuth client ID has rotated; the refresh token is unusable.
    throw new NotLoggedInError(
      `Stored credentials were issued by a different OAuth client (${parsed.client_id}). The Hub may have rotated its public client; re-run \`dockerhub login\`.`,
    );
  }
  return parsed;
}

/** Write credentials atomically (temp file + rename) with mode 0600. */
export async function writeCredentials(creds: StoredCredentials): Promise<void> {
  await ensureDataDir();
  const target = getAuthFilePath();
  const tmp = `${target}.tmp.${process.pid}.${Date.now()}`;
  let renamed = false;
  try {
    await writeFile(tmp, JSON.stringify(creds, null, 2) + "\n", {
      mode: AUTH_FILE_MODE,
    });
    await chmod(tmp, AUTH_FILE_MODE);
    await rename(tmp, target);
    renamed = true;
  } catch (err) {
    throw new StorageError(
      `Could not write auth file: ${(err as Error).message}`,
      err,
    );
  } finally {
    if (!renamed) {
      try {
        await unlink(tmp);
      } catch {
        // ignore
      }
    }
  }
}

/** Delete the auth file. No-op if already absent. */
export async function deleteCredentials(): Promise<void> {
  try {
    await unlink(getAuthFilePath());
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return;
    throw new StorageError(
      `Could not delete auth file: ${(err as Error).message}`,
      err,
    );
  }
}

/** Returns true if the auth file exists. */
export async function credentialsExist(): Promise<boolean> {
  try {
    await stat(getAuthFilePath());
    return true;
  } catch {
    return false;
  }
}

// ----- Single-flight locking (ADR-0003) -----

export interface FileLock {
  release(): Promise<void>;
}

/**
 * Run `fn` while holding an exclusive cross-process lock on the auth
 * directory. The lock is implemented as a PID file with O_EXCL atomic
 * create — portable to macOS, Linux, and Windows without native
 * dependencies.
 */
export async function withFileLock<T>(fn: () => Promise<T>): Promise<T> {
  await ensureDataDir();
  const lock = await acquireLock(getLockFilePath());
  try {
    return await fn();
  } finally {
    await lock.release();
  }
}

async function acquireLock(lockPath: string): Promise<FileLock> {
  const start = Date.now();
  while (true) {
    if (Date.now() - start > LOCK_TIMEOUT_MS) {
      throw new StorageError(
        `Could not acquire lock at ${lockPath} within ${LOCK_TIMEOUT_MS}ms. Another dockerhub-cli invocation may be hung.`,
      );
    }
    let fh;
    try {
      fh = await open(lockPath, "wx");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") {
        throw new StorageError(`Lock error: ${(err as Error).message}`, err);
      }
      const holder = await readHolderPid(lockPath);
      if (holder === null) {
        // Lockfile exists but has no PID written yet — the holder is
        // mid-acquire (between open(O_EXCL) and writeFile). Wait and
        // retry; never steal here, since stealing would let two callers
        // both hold the lock.
        await sleep(LOCK_RETRY_MS);
        continue;
      }
      if (isProcessAlive(holder)) {
        await sleep(LOCK_RETRY_MS);
        continue;
      }
      // Lockfile contains a valid PID and that process is dead.
      // Safe to steal.
      try {
        await unlink(lockPath);
      } catch {
        // May have been unlinked by another contender; loop will retry.
      }
      continue;
    }
    try {
      await writeFile(fh, String(process.pid));
    } finally {
      await fh.close();
    }
    return {
      release: async () => {
        try {
          await unlink(lockPath);
        } catch {
          // Best effort; next acquire will steal after timeout.
        }
      },
    };
  }
}

async function readHolderPid(lockPath: string): Promise<number | null> {
  try {
    const raw = await readFile(lockPath, "utf8");
    const pid = parseInt(raw.trim(), 10);
    return Number.isFinite(pid) && pid > 0 ? pid : null;
  } catch {
    return null;
  }
}

function isProcessAlive(pid: number): boolean {
  if (pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    // EPERM means the process exists but we lack permission to signal it.
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ----- In-memory access-token cache -----

let _cache: AccessTokenCache | null = null;

export function setAccessTokenCache(cache: AccessTokenCache): void {
  _cache = cache;
}

export function getAccessTokenCache(): AccessTokenCache | null {
  return _cache;
}

export function clearAccessTokenCache(): void {
  _cache = null;
}

/**
 * Returns true if `cache.expires_at` is more than `skewMs` away from
 * `now`. The skew prevents using a token that's about to expire.
 */
export function isAccessTokenFresh(
  cache: AccessTokenCache,
  skewMs: number = ACCESS_TOKEN_SKEW_MS,
  now: number = Date.now(),
): boolean {
  return cache.expires_at - now > skewMs;
}