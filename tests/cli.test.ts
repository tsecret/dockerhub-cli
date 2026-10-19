/**
 * End-to-end smoke test: spawn the CLI as a subprocess against the
 * mock server, verify the wrapper works for the no-network commands.
 *
 * Tests that require browser flow are not run here; those are
 * covered by tests/auth.test.ts.
 */

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { setDataDir } from "../src/paths.ts";
import { clearAccessTokenCache } from "../src/store.ts";

const CLI = join(import.meta.dir, "..", "src", "cli.ts");

let tmpDir: string;

beforeEach(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), "dockerhub-cli-test-"));
  setDataDir(tmpDir);
});

afterEach(async () => {
  setDataDir(null);
  clearAccessTokenCache();
  await rm(tmpDir, { recursive: true, force: true });
});

async function runCli(
  args: string[],
  env: Record<string, string> = {},
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const proc = Bun.spawn(["bun", "run", CLI, ...args], {
    env: {
      ...process.env,
      ...env,
      NO_COLOR: "1",
      // Isolate from the developer's real ~/.config/dockerhub/auth.json
      // so "not logged in" tests can run deterministically.
      DOCKERHUB_CONFIG_DIR: tmpDir,
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  const exitCode = await proc.exited;
  return { stdout, stderr, exitCode };
}

describe("dockerhub CLI smoke", () => {
  test("--version prints version", async () => {
    const { stdout, exitCode } = await runCli(["--version"]);
    expect(exitCode).toBe(0);
    expect(stdout).toMatch(/dockerhub\/0\.1\.4/);
  });

  test("--help lists commands", async () => {
    const { stdout, exitCode } = await runCli(["--help"]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain("login");
    expect(stdout).toContain("logout");
    expect(stdout).toContain("whoami");
    expect(stdout).toContain("token");
    expect(stdout).toContain("list");
    expect(stdout).toContain("create");
    expect(stdout).toContain("delete");
  });

  test("whoami without login returns NotLoggedInError (exit 2)", async () => {
    const { stderr, exitCode } = await runCli(["whoami"]);
    expect(exitCode).toBe(2);
    expect(stderr).toContain("Not logged in");
    expect(stderr).toContain("dockerhub login");
  });

  test("token list without login returns NotLoggedInError (exit 2)", async () => {
    const { stderr, exitCode } = await runCli(["token", "list"]);
    expect(exitCode).toBe(2);
    expect(stderr).toContain("Not logged in");
  });

  test("unknown subcommand exits with usage error (exit 64)", async () => {
    const { stderr, exitCode } = await runCli(["token", "frobnicate"]);
    expect(exitCode).toBe(64);
    expect(stderr).toContain("Error");
  });

  test("no args shows help and quickstart (exit 0)", async () => {
    const { stdout, exitCode } = await runCli([]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain("login");
    expect(stdout).toContain("logout");
    expect(stdout).toContain("whoami");
    expect(stdout).toContain("Quickstart");
  });

  test("token create without --label shows error + usage", async () => {
    const { stderr, exitCode } = await runCli(["token", "create"]);
    expect(exitCode).toBe(64);
    expect(stderr).toContain("--label is required");
    // The full usage block should be printed too.
    expect(stderr).toContain("Usage: dockerhub token create");
    expect(stderr).toContain("--label <name>");
    expect(stderr).toContain("--scopes <csv>");
    expect(stderr).toContain("Examples:");
  });

  test("token inspect without uuid shows error + usage", async () => {
    const { stderr, exitCode } = await runCli(["token", "inspect"]);
    expect(exitCode).toBe(64);
    expect(stderr).toContain("Missing required argument: <uuid>");
    expect(stderr).toContain("Usage: dockerhub token inspect");
  });

  test("token delete without uuid shows error + usage", async () => {
    const { stderr, exitCode } = await runCli(["token", "delete"]);
    expect(exitCode).toBe(64);
    expect(stderr).toContain("Missing required argument");
    expect(stderr).toContain("Usage: dockerhub token delete");
    expect(stderr).toContain("without confirmation");
  });

  test("token delete is wired (no prompt, no --force)", async () => {
    // The previous --force flag is gone; the action runs without prompts.
    // (The actual delete would fail with NotLoggedIn since DOCKERHUB_CONFIG_DIR
    // is set to a temp dir in tests.)
    const { stderr, exitCode } = await runCli([
      "token",
      "delete",
      "abc-123",
      "def-456",
    ]);
    // Expect NotLoggedIn (exit 2) — proving no confirmation prompt was shown
    // and the action actually proceeded.
    expect(exitCode).toBe(2);
    expect(stderr).toContain("Not logged in");
  });

  test("token create with bad --expires shows error + usage", async () => {
    const { stderr, exitCode } = await runCli([
      "token",
      "create",
      "--label",
      "x",
      "--expires",
      "tomorrow",
    ]);
    // "tomorrow" doesn't match the relative format
    expect(exitCode).toBe(64);
    expect(stderr).toContain("Invalid --expires");
    expect(stderr).toContain("Usage: dockerhub token create");
  });

  test("--json emits errors as JSON", async () => {
    const { stderr, exitCode } = await runCli(["--json", "whoami"]);
    expect(exitCode).toBe(2);
    const parsed = JSON.parse(stderr.trim());
    expect(parsed.code).toBe(2);
    expect(parsed.error).toContain("Not logged in");
  });
});