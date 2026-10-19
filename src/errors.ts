/**
 * Error model and exit codes for dockerhub-cli.
 *
 * Exit codes:
 *   0   success
 *   1   general / unspecified error
 *   2   not logged in (auth file missing or unreadable)
 *   3   session expired (refresh rejected; user must `dockerhub login`)
 *   4   insufficient permission (Hub rejected with 403)
 *   5   rate limited (Hub returned 429)
 *   6   other Hub error (400/404/500 etc.)
 *   64+ CLI usage errors, mirroring sysexits.h conventions:
 *         64 EX_USAGE, 65 EX_DATAERR, 66 EX_NOINPUT, 67 EX_NOUSER,
 *         68 EX_NOHOST, 69 EX_UNAVAILABLE, 70 EX_SOFTWARE,
 *         71 EX_OSERR, 72 EX_OSFILE, 73 EX_CANTCREAT,
 *         74 EX_IOERR, 75 EX_TEMPFAIL, 76 EX_PROTOCOL,
 *         77 EX_NOPERM, 78 EX_CONFIG
 */

import type { HubErrorBody, OAuthErrorBody } from "./types.ts";

/** Symbolic exit codes. Numeric values are part of the public API. */
export const ExitCode = {
  Success: 0,
  GeneralError: 1,
  NotLoggedIn: 2,
  SessionExpired: 3,
  InsufficientPermission: 4,
  RateLimited: 5,
  HubError: 6,

  // sysexits.h-aligned usage errors
  Usage: 64,
  DataFormat: 65,
  NoInput: 66,
  NoUser: 67,
  NoHost: 68,
  Unavailable: 69,
  Software: 70,
  OSError: 71,
  OSFile: 72,
  CantCreate: 73,
  IOError: 74,
  TempFail: 75,
  Protocol: 76,
  NoPerm: 77,
  Config: 78,
} as const;

export type ExitCodeValue = (typeof ExitCode)[keyof typeof ExitCode];

/** Base class for all errors raised by dockerhub-cli. */
export class CLIError extends Error {
  readonly exitCode: ExitCodeValue;
  /** Optional actionable hint printed to stderr. */
  readonly hint?: string;
  /** Optional upstream detail (HTTP body, JWT claim, etc.). */
  readonly detail?: string;
  /** Optional usage block printed after the error message. */
  readonly usage?: string;

  constructor(
    message: string,
    options: {
      exitCode?: ExitCodeValue;
      hint?: string;
      detail?: string;
      usage?: string;
      cause?: unknown;
    } = {},
  ) {
    super(message);
    this.name = "CLIError";
    this.exitCode = options.exitCode ?? ExitCode.GeneralError;
    this.hint = options.hint;
    this.detail = options.detail;
    this.usage = options.usage;
    if (options.cause !== undefined) {
      (this as { cause?: unknown }).cause = options.cause;
    }
  }
}

/** No stored credentials; user must log in. */
export class NotLoggedInError extends CLIError {
  constructor(
    message = "Not logged in. Run `dockerhub login` to authenticate.",
    detail?: string,
  ) {
    super(message, {
      exitCode: ExitCode.NotLoggedIn,
      hint: "dockerhub login",
      detail,
    });
  }
}

/** Refresh token was rejected. Family may have been revoked. */
export class SessionExpiredError extends CLIError {
  constructor(
    message = "Session expired. Run `dockerhub login` to re-authenticate.",
    detail?: string,
  ) {
    super(message, {
      exitCode: ExitCode.SessionExpired,
      hint: "dockerhub login",
      detail,
    });
  }
}

/** Hub returned 403 — token works but lacks scope. */
export class InsufficientPermissionError extends CLIError {
  constructor(message = "Insufficient permission.", detail?: string) {
    super(message, {
      exitCode: ExitCode.InsufficientPermission,
      hint: "Re-run `dockerhub login` — if the problem persists, your Docker Hub account may lack access to this endpoint.",
      detail,
    });
  }
}

/** Hub returned 429. Includes the retry-after hint if Hub provided one. */
export class RateLimitedError extends CLIError {
  readonly retryAfterSeconds?: number;

  constructor(
    retryAfterSeconds: number | undefined,
    message = "Docker Hub rate limit hit.",
  ) {
    super(message, {
      exitCode: ExitCode.RateLimited,
      hint: retryAfterSeconds
        ? `Retry in ${retryAfterSeconds}s.`
        : "Retry shortly.",
    });
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/** Generic Hub API error (anything not mapped above). */
export class HubError extends CLIError {
  readonly httpStatus: number;

  constructor(httpStatus: number, message: string, detail?: string) {
    super(message, { exitCode: ExitCode.HubError, detail });
    this.httpStatus = httpStatus;
  }
}

/** Hub-specific: "token issued from personal access token is not allowed". */
export class PATTokenRejectedError extends CLIError {
  constructor(detail?: string) {
    super(
      "Hub rejected the bearer token (issued from a personal access token).",
      {
        exitCode: ExitCode.InsufficientPermission,
        hint: "This is a Hub-side policy, not a dockerhub-cli bug. See ADR-0007 and ADR-0001.",
        detail,
      },
    );
  }
}

/** User passed a bad flag combination. */
export class UsageError extends CLIError {
  constructor(
    message: string,
    options: { hint?: string; usage?: string } = {},
  ) {
    super(message, {
      exitCode: ExitCode.Usage,
      hint: options.hint,
      usage: options.usage,
    });
  }
}

/** File system / I/O error during read or write of the auth file. */
export class StorageError extends CLIError {
  constructor(message: string, cause?: unknown) {
    super(message, {
      exitCode: ExitCode.OSFile,
      cause,
      hint: "Check filesystem permissions on ~/.config/dockerhub/",
    });
  }
}

/** Refresh failed because the family was revoked (reuse detection). */
export class TokenFamilyRevokedError extends CLIError {
  constructor(detail?: string) {
    super(
      "Refresh token family was revoked. Re-authentication required.",
      {
        exitCode: ExitCode.SessionExpired,
        hint: "dockerhub login — likely caused by a concurrent CLI invocation refreshing the same token before this one.",
        detail,
      },
    );
  }
}

/**
 * Translate an Auth0 error body into a CLIError. The mapping follows
 * ADR-0003 and ADR-0007.
 */
export function fromAuth0Error(
  body: OAuthErrorBody,
  httpStatus: number,
): CLIError {
  switch (body.error) {
    case "invalid_grant":
      // Most likely refresh-token revoked or family-revoked.
      if (httpStatus === 403) {
        return new TokenFamilyRevokedError(body.error_description);
      }
      return new SessionExpiredError(body.error_description);
    case "authorization_pending":
      // Should not surface to the user — the polling loop handles it.
      return new CLIError("Authorization still pending.", {
        exitCode: ExitCode.GeneralError,
        detail: body.error_description,
      });
    case "slow_down":
      return new CLIError("Polling too fast; backing off.", {
        exitCode: ExitCode.GeneralError,
        detail: body.error_description,
      });
    case "expired_token":
      return new CLIError("Device code expired before authorization.", {
        exitCode: ExitCode.GeneralError,
        hint: "Re-run `dockerhub login`.",
        detail: body.error_description,
      });
    case "access_denied":
      return new CLIError("Authorization denied.", {
        exitCode: ExitCode.NoUser,
        hint: "You declined the device-code authorization in the browser.",
        detail: body.error_description,
      });
    default:
      return new CLIError(`Auth0 error: ${body.error}`, {
        exitCode: ExitCode.HubError,
        detail: body.error_description,
      });
  }
}

/** Translate a Hub API error response into a CLIError. */
export function fromHubError(httpStatus: number, body: HubErrorBody): CLIError {
  const message =
    body.detail ?? body.message ?? `Hub returned HTTP ${httpStatus}.`;

  if (
    typeof body.detail === "string" &&
    body.detail.includes("issued from personal access token")
  ) {
    return new PATTokenRejectedError(body.detail);
  }

  if (httpStatus === 401) {
    return new SessionExpiredError(message);
  }
  if (httpStatus === 403) {
    return new InsufficientPermissionError(message);
  }
  if (httpStatus === 404) {
    return new HubError(httpStatus, message, JSON.stringify(body));
  }
  if (httpStatus === 429) {
    // The retry-after hint comes from a header, not the body; the caller
    // is expected to pass it via fromHubErrorWithRetryAfter for that.
    return new RateLimitedError(undefined, message);
  }
  return new HubError(httpStatus, message, JSON.stringify(body));
}

/**
 * Format a CLIError for human display. Always goes to stderr.
 * Includes the message, the optional usage block, the optional hint,
 * and (if present) the detail.
 */
export function formatErrorForHuman(err: CLIError): string {
  const lines: string[] = [`Error: ${err.message}`];
  if (err.detail) {
    lines.push(`  ${err.detail}`);
  }
  if (err.usage) {
    lines.push("");
    lines.push(err.usage);
  }
  if (err.hint) {
    lines.push(`Hint: ${err.hint}`);
  }
  return lines.join("\n");
}

/**
 * Format a CLIError as a single object suitable for `--json` output.
 * Schema is stable across versions — scripts depend on it.
 */
export function formatErrorAsJSON(err: CLIError): {
  error: string;
  code: number;
  hint?: string;
  detail?: string;
  usage?: string;
} {
  return {
    error: err.message,
    code: err.exitCode,
    ...(err.hint ? { hint: err.hint } : {}),
    ...(err.detail ? { detail: err.detail } : {}),
    ...(err.usage ? { usage: err.usage } : {}),
  };
}