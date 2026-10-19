/**
 * XDG-aware data directory resolver.
 *
 * Returns the directory where the auth file and lockfile live. Honors
 * $XDG_CONFIG_HOME on POSIX, falls back to ~/.config, and uses
 * %AppData% on Windows. The directory name is `dockerhub` to match the
 * npm package name (`dockerhub-cli`).
 */

import { homedir } from "node:os";
import { join } from "node:path";

const DIR_NAME = "dockerhub";

let cached: string | null = null;

/** Override the data directory (used by tests). Pass null to clear. */
export function setDataDir(path: string | null): void {
  cached = path;
}

export function getDataDir(): string {
  if (cached !== null) return cached;
  // Explicit override (used by tests and by users who want isolated
  // sessions for separate accounts — e.g. work + personal).
  const override = process.env.DOCKERHUB_CONFIG_DIR;
  if (override && override.trim()) {
    cached = override;
    return cached;
  }
  let base: string;
  const xdg = process.env.XDG_CONFIG_HOME;
  if (xdg && xdg.trim()) {
    base = xdg;
  } else if (process.platform === "win32") {
    base = process.env.APPDATA ?? join(homedir(), "AppData", "Roaming");
  } else {
    base = join(homedir(), ".config");
  }
  cached = join(base, DIR_NAME);
  return cached;
}

export function getAuthFilePath(): string {
  return join(getDataDir(), "auth.json");
}

export function getLockFilePath(): string {
  return join(getDataDir(), ".lock");
}