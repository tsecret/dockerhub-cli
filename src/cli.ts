#!/usr/bin/env node
/**
 * dockerhub — CLI entry point.
 *
 * Subcommands:
 *   dockerhub login [--no-browser]
 *   dockerhub logout
 *   dockerhub whoami [--json]
 *   dockerhub token list [--json]
 *   dockerhub token inspect <uuid> [--json]
 *   dockerhub token create --label <name> [--scopes <csv>] [--expires <date>] [--json]
 *   dockerhub token delete <uuid> [<uuid>...] [--json]
 *   dockerhub --version
 *   dockerhub --help
 *
 * Note on cac: this CLI parser does not natively support nested
 * sub-commands. The `token <sub>` subtree uses variadic args with a
 * single dispatcher action that routes to list/inspect/create/delete.
 *
 * Global flag:
 *   --json   emit errors as JSON instead of human text. Per-command
 *            --json is independent and controls payload format.
 */

import { cac, type CAC } from "cac";
import { getFreshAccessToken, login, logout } from "./auth.ts";
import {
  CLIError,
  ExitCode,
  formatErrorAsJSON,
  formatErrorForHuman,
  UsageError,
} from "./errors.ts";
import { HubClient, validateScopes } from "./hub.ts";
import {
  formatCreatedPAT,
  formatPAT,
  formatPATList,
  toJSON,
} from "./output.ts";
import { getAuthFilePath } from "./paths.ts";
import type { OutputOptions } from "./types.ts";
import {
  HUB_PAT_SCOPES,
  type CreateHubPATRequest,
  type HubPATScope,
} from "./types.ts";

const cli: CAC = cac("dockerhub");

cli.option("--json", "Emit errors as JSON instead of human text");

// ----- Top-level commands -----

cli
  .command("login", "Authenticate via OAuth device-code flow")
  .option("--no-browser", "Skip auto-opening browser; print URL only")
  .action(
    async (options: { browser?: boolean; json?: boolean }) => {
      const { username } = await login({
        onDeviceCode: (d) => {
          process.stderr.write(
            `\nDocker Hub is asking you to sign in:\n` +
              `  User code:  ${d.user_code}\n` +
              `  Verify URL: ${d.verification_uri_complete}\n` +
              `\nThe URL has been opened in your browser. ` +
              `Complete the sign-in (including 2FA if enabled).\n\n`,
          );
        },
        onPolling: (attempt, secs) => {
          if (attempt === 1 || attempt % 6 === 0) {
            process.stderr.write(
              `  waiting for browser authorization... (${secs}s left)\n`,
            );
          }
        },
        browserOpener:
          options.browser === false
            ? async () => {
                /* user opens manually */
              }
            : undefined,
      });
      const configPath = getAuthFilePath();
      if (options.json) {
        process.stdout.write(
          `${toJSON(
            {
              username,
              config_path: configPath,
              next: [
                "dockerhub token list",
                "dockerhub token create --label <name>",
                "dockerhub whoami",
              ],
            },
            { json: true },
          )}\n`,
        );
      } else {
        process.stdout.write(
          `\nLogged in.\n\n` +
            `  Username: ${username}\n` +
            `  Session:  ${configPath}\n\n` +
            `Try next:\n` +
            `  dockerhub token list                              # see your existing tokens\n` +
            `  dockerhub token create --label "my token"         # mint a new personal access token\n` +
            `  dockerhub token inspect <uuid>                    # see details for one token\n\n` +
            `Sign out:  dockerhub logout\n`,
        );
      }
    },
  );

cli
  .command("logout", "Revoke session and erase local credentials")
  .option("--json", "Output as JSON")
  .action(async (options: OutputOptions) => {
    const configPath = getAuthFilePath();
    let wasLoggedIn = true;
    try {
      await logout();
    } catch (err) {
      if (err instanceof CLIError && err.exitCode === ExitCode.NotLoggedIn) {
        wasLoggedIn = false;
      } else {
        throw err;
      }
    }
    if (options.json) {
      process.stdout.write(
        `${toJSON({ was_logged_in: wasLoggedIn, config_path: configPath }, { json: true })}\n`,
      );
    } else {
      if (wasLoggedIn) {
        process.stdout.write(
          `Revoked server-side session.\nCleared local credentials at ${configPath}.\nLogged out.\n`,
        );
      } else {
        process.stdout.write(`Nothing to do — you were not logged in.\n`);
      }
    }
  });

cli
  .command("whoami", "Print your Docker Hub username")
  .option("--json", "Output as JSON")
  .action(async (options: OutputOptions) => {
    const hub = new HubClient({
      getAccessToken: () => getFreshAccessToken(),
    });
    const { username, email } = await hub.getCurrentUser();
    if (options.json) {
      process.stdout.write(
        `${toJSON({ username, ...(email ? { email } : {}) }, { json: true })}\n`,
      );
    } else {
      process.stdout.write(`${username}\n`);
    }
  });

// ----- `token` subtree (single variadic command) -----

cli
  .command(
    "token [...args]",
    "Manage Docker Hub personal access tokens. Subcommands: list, inspect <uuid>, create, delete <uuid>",
  )
  .option("--json", "Output as JSON")
  .option("--label <label>", "Token label (for `token create`)")
  .option(
    "--scopes <scopes>",
    `Comma-separated scopes (for \`token create\`). Valid: ${HUB_PAT_SCOPES.join(", ")}. Default: repo:read`,
    { default: "repo:read" },
  )
  .option(
    "--expires <value>",
    "Expiry (RFC3339 or relative: 30d, 12h, 1y, 6w, 3M)",
  )
  .action(
    async (
      args: string[],
      options: OutputOptions & {
        label?: string;
        scopes?: string;
        expires?: string;
        force?: boolean;
      },
    ) => {
      const [sub, ...rest] = args;
      const freshToken = () => getFreshAccessToken();

      switch (sub) {
        case undefined:
        case "help":
        case "--help":
        case "-h": {
          process.stdout.write(tokenSubcommandHelp());
          return;
        }

        case "list": {
          if (rest.length > 0) {
            throw new UsageError(`Unexpected args after 'list': ${rest.join(" ")}`);
          }
          const hub = new HubClient({ getAccessToken: freshToken });
          const { results } = await hub.listTokens();
          if (results.length === 0) {
            process.stdout.write(options.json
              ? `${toJSON({ count: 0, results: [] }, { json: true })}\n`
              : `No tokens. Create one with: dockerhub token create --label "my token"\n`);
            return;
          }
          process.stdout.write(`${formatPATList(results, options)}\n`);
          return;
        }

        case "inspect": {
          const uuid = rest[0];
          if (!uuid) {
            throw new UsageError("Missing required argument: <uuid>", {
              usage: usageTokenInspect(),
            });
          }
          if (rest.length > 1) {
            throw new UsageError(`Unexpected args after uuid: ${rest.slice(1).join(" ")}`);
          }
          const hub = new HubClient({ getAccessToken: freshToken });
          const pat = await hub.inspectToken(uuid);
          process.stdout.write(`${formatPAT(pat, options)}\n`);
          return;
        }

        case "create": {
          if (!options.label || !options.label.trim()) {
            throw new UsageError("--label is required.", {
              usage: usageTokenCreate(),
            });
          }
          const scopes = (options.scopes ?? "repo:read")
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean);
          if (scopes.length === 0) {
            throw new UsageError("--scopes must list at least one scope.", {
              usage: usageTokenCreate(),
            });
          }
          try {
            validateScopes(scopes);
          } catch (err) {
            if (err instanceof CLIError) {
              throw new UsageError(err.message, { usage: usageTokenCreate() });
            }
            throw err;
          }
          const req: CreateHubPATRequest = {
            token_label: options.label,
            scopes: scopes as HubPATScope[],
          };
          if (options.expires) {
            try {
              req.expires_at = parseExpiry(options.expires);
            } catch (err) {
              if (err instanceof CLIError) {
                throw new UsageError(err.message, { usage: usageTokenCreate() });
              }
              throw err;
            }
          }
          const hub = new HubClient({ getAccessToken: freshToken });
          const pat = await hub.createToken(req);
          if (options.json) {
            process.stdout.write(`${toJSON(pat, { json: true })}\n`);
          } else {
            const { stdout, stderr } = formatCreatedPAT(pat);
            process.stdout.write(`${stdout}\n`);
            process.stderr.write(stderr);
          }
          return;
        }

        case "delete": {
          if (rest.length === 0) {
            throw new UsageError("Missing required argument: <uuid>...", {
              usage: usageTokenDelete(),
            });
          }
          const uuids = rest;
          // Fetch the access token ONCE up front. Auth errors (NotLoggedIn,
          // SessionExpired) are session-wide and should propagate to the
          // top-level error handler, not be reported as a "this UUID
          // failed" entry. Per-UUID failures (404, 429, etc.) are caught
          // inside the loop below.
          const accessToken = await getFreshAccessToken();
          const hub = new HubClient({
            getAccessToken: async () => accessToken,
          });
          const deleted: string[] = [];
          const failed: Array<{ uuid: string; error: string }> = [];
          for (const uuid of uuids) {
            try {
              await hub.deleteToken(uuid);
              deleted.push(uuid);
            } catch (err) {
              failed.push({
                uuid,
                error: err instanceof Error ? err.message : String(err),
              });
            }
          }
          if (options.json) {
            process.stdout.write(
              `${toJSON(
                {
                  deleted,
                  ...(failed.length > 0 ? { failed } : {}),
                },
                { json: true },
              )}\n`,
            );
          } else {
            for (const uuid of deleted) {
              process.stdout.write(`Deleted ${uuid}\n`);
            }
            for (const f of failed) {
              process.stderr.write(`Failed ${f.uuid}: ${f.error}\n`);
            }
          }
          if (failed.length > 0) {
            process.exitCode = 1;
          }
          return;
        }

        default:
          throw new UsageError(
            `Unknown token subcommand: ${sub}. Run \`dockerhub token --help\` for usage.`,
          );
      }
    },
  );

cli.help((sections) => {
  // Append a Quickstart section after cac's default sections.
  return [
    ...sections,
    {
      title: "Quickstart",
      body:
        "  1. dockerhub login                            authenticate via browser\n" +
        "  2. dockerhub token list                       see your existing tokens\n" +
        "  3. dockerhub token create --label \"my token\"  mint a new personal access token",
    },
  ];
});
cli.version("0.1.4");

// ----- Helpers -----

function parseExpiry(input: string): string {
  const trimmed = input.trim();
  if (/^\d{4}-\d{2}-\d{2}T/.test(trimmed)) {
    const d = new Date(trimmed);
    if (Number.isNaN(d.getTime())) {
      throw new UsageError(
        `Invalid --expires value: ${input} (not a valid date).`,
      );
    }
    return d.toISOString();
  }
  const m = /^(\d+)([shdwyM])$/.exec(trimmed);
  if (!m) {
    throw new UsageError(
      `Invalid --expires value: ${input}. Use RFC3339 (e.g. 2026-12-31T23:59:59Z) or relative (e.g. 30d, 1y, 12h, 6w, 3M).`,
    );
  }
  const n = parseInt(m[1] as string, 10);
  const unit = m[2] as string;
  const ms: Record<string, number> = {
    s: 1_000,
    h: 3_600_000,
    d: 86_400_000,
    w: 7 * 86_400_000,
    M: 30 * 86_400_000,
    y: 365 * 86_400_000,
  };
  return new Date(Date.now() + n * (ms[unit] as number)).toISOString();
}

function tokenSubcommandHelp(): string {
  return [
    "Manage Docker Hub personal access tokens.",
    "",
    "Subcommands:",
    "  list                                  List all tokens",
    "  inspect <uuid>                        Show details for one token",
    "  create --label <name> [--scopes <csv>] [--expires <date>]   Create a token",
    "  delete <uuid> [<uuid>...]             Delete one or more tokens (no confirmation)",
    "",
    "Examples:",
    "  dockerhub token list",
    "  dockerhub token list --json",
    "  dockerhub token inspect 83f7baa8-1220-458f-9e1d-3397566bfe1a",
    `  dockerhub token create --label "ci deploy" --scopes repo:read,repo:write`,
    `  dockerhub token create --label "30-day temp" --expires 30d`,
    "  dockerhub token delete 83f7baa8-1220-458f-9e1d-3397566bfe1a",
    "  dockerhub token delete abc-123 def-456 ghi-789",
    "",
  ].join("\n");
}

const SCOPES_LIST = HUB_PAT_SCOPES.join(", ");

function usageTokenCreate(): string {
  return [
    "Usage: dockerhub token create --label <name> [--scopes <csv>] [--expires <date>]",
    "",
    "Options:",
    "  --label <name>      Required. The token's display name.",
    `  --scopes <csv>      Comma-separated scopes. Valid: ${SCOPES_LIST}. Default: repo:read.`,
    "  --expires <value>   Optional. RFC3339 (e.g. 2026-12-31T23:59:59Z) or relative",
    "                     (30d, 12h, 1y, 6w, 3M). Omit for no expiry.",
    "",
    "Examples:",
    `  dockerhub token create --label "ci deploy" --scopes repo:read,repo:write`,
    `  dockerhub token create --label "30-day temp" --expires 30d`,
    `  dockerhub token create --label "scoped" --scopes repo:admin --expires 2026-12-31T23:59:59Z`,
  ].join("\n");
}

function usageTokenInspect(): string {
  return [
    "Usage: dockerhub token inspect <uuid>",
    "",
    "Arguments:",
    "  <uuid>    Required. The token's UUID (find it via `dockerhub token list`).",
  ].join("\n");
}

function usageTokenDelete(): string {
  return [
    "Usage: dockerhub token delete <uuid> [<uuid>...]",
    "",
    "Arguments:",
    "  <uuid>    One or more token UUIDs to delete. Find UUIDs via `dockerhub token list`.",
    "",
    "Tokens are deleted without confirmation. If any UUID is invalid or already gone,",
    "the others still succeed; the bad ones are reported.",
    "",
    "Examples:",
    "  dockerhub token delete 83f7baa8-1220-458f-9e1d-3397566bfe1a",
    "  dockerhub token delete abc-123 def-456 ghi-789",
  ].join("\n");
}

// ----- Top-level error handler -----

try {
  // cac's parse() does not await async actions — it returns before
  // the action's promise resolves. We pass run: false and invoke
  // runMatchedCommand() ourselves so we can await it.
  cli.parse(process.argv, { run: false });
  if (!cli.matchedCommand) {
    // No command matched and no --help/--version. Print help + quickstart.
    cli.outputHelp();
    process.stdout.write("\n");
  } else {
    await cli.runMatchedCommand();
  }
} catch (err) {
  if (err instanceof CLIError) {
    const isJSON = Boolean(cli.options.json);
    if (isJSON) {
      process.stderr.write(`${JSON.stringify(formatErrorAsJSON(err))}\n`);
    } else {
      process.stderr.write(`${formatErrorForHuman(err)}\n`);
    }
    process.exit(err.exitCode);
  }
  // cac's own error (unknown command, missing required arg, etc.)
  const message = (err as Error)?.message ?? String(err);
  process.stderr.write(`Error: ${message}\n`);
  if (cli.options.help) {
    process.stderr.write("\nRun `dockerhub --help` for usage.\n");
  }
  process.exit(ExitCode.Usage);
}