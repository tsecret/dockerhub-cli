/**
 * Runtime type guards for the external API response bodies we accept.
 *
 * `JSON.parse` returns `any` (loosely: `unknown`). We pin the fields we
 * actually depend on, throw `CLIError` early if the API drifts, and
 * let TypeScript narrow from there. This replaces a chain of `as never`
 * / `as unknown as T` casts that would silently propagate missing
 * fields into the access-token cache and Hub response handling.
 */

import { CLIError, ExitCode } from "./errors.ts";
import type {
  DeviceCodeResponse,
  HubErrorBody,
  OAuthErrorBody,
  TokenResponse,
} from "./types.ts";

function reject(message: string, detail?: string): never {
  throw new CLIError(message, {
    exitCode: ExitCode.HubError,
    hint: "The API response shape may have changed. Run `dockerhub login` again, and if the problem persists file an issue.",
    detail,
  });
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function expectString(obj: Record<string, unknown>, key: string): string {
  const v = obj[key];
  if (typeof v !== "string") reject(`Expected string at \`${key}\`.`, JSON.stringify(v));
  return v as string;
}

function expectNumber(obj: Record<string, unknown>, key: string): number {
  const v = obj[key];
  if (typeof v !== "number") reject(`Expected number at \`${key}\`.`, JSON.stringify(v));
  return v as number;
}

function optionalString(obj: Record<string, unknown>, key: string): string | undefined {
  const v = obj[key];
  if (v === undefined) return undefined;
  if (typeof v !== "string") reject(`Expected string at \`${key}\`.`, JSON.stringify(v));
  return v as string;
}

/** Validate the Auth0 device-code response. */
export function parseDeviceCodeResponse(body: unknown): DeviceCodeResponse {
  if (!isObject(body)) reject("Device code response was not a JSON object.");
  return {
    device_code: expectString(body, "device_code"),
    user_code: expectString(body, "user_code"),
    verification_uri: expectString(body, "verification_uri"),
    verification_uri_complete: expectString(body, "verification_uri_complete"),
    expires_in: expectNumber(body, "expires_in"),
    interval: expectNumber(body, "interval"),
  };
}

/** Validate a successful token response (device-code grant or refresh grant). */
export function parseTokenResponse(body: unknown): TokenResponse {
  if (!isObject(body)) reject("Token response was not a JSON object.");
  return {
    access_token: expectString(body, "access_token"),
    id_token: optionalString(body, "id_token"),
    refresh_token: optionalString(body, "refresh_token"),
    expires_in: expectNumber(body, "expires_in"),
    token_type: expectString(body, "token_type"),
    scope: optionalString(body, "scope") ?? "",
  };
}

/** Validate an Auth0 error response. */
export function parseOAuthErrorBody(body: unknown): OAuthErrorBody {
  if (!isObject(body)) reject("Auth0 error response was not a JSON object.");
  return {
    error: expectString(body, "error") as OAuthErrorBody["error"],
    error_description: optionalString(body, "error_description"),
  };
}

/** Validate a Hub API error response. */
export function parseHubErrorBody(body: unknown): HubErrorBody {
  if (!isObject(body)) {
    // Some Hub errors return empty bodies (e.g. 502 from a proxy).
    return {};
  }
  return {
    detail: optionalString(body, "detail"),
    message: optionalString(body, "message"),
    code: optionalString(body, "code"),
  };
}