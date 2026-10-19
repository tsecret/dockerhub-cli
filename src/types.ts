/**
 * Type definitions for dockerhub-cli.
 *
 * Every external shape we accept or return is pinned here so the rest
 * of the codebase has one source of truth. Response shapes are pinned
 * against the real Auth0 / Hub responses captured in Phase 0 — see
 * the `results` array in ADR-0001 for the Hub PAT shape.
 */

// ----- Auth0 (login.docker.com) -----

/** Response from POST /oauth/device/code. */
export interface DeviceCodeResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  expires_in: number;
  interval: number;
}

/** Response from POST /oauth/token on a successful grant. */
export interface TokenResponse {
  access_token: string;
  id_token?: string;
  refresh_token?: string;
  expires_in: number;
  token_type: string;
  scope: string;
}

/** Response from POST /oauth/token on a failed grant. */
export interface OAuthErrorBody {
  error:
    | "authorization_pending"
    | "slow_down"
    | "expired_token"
    | "access_denied"
    | "invalid_grant"
    | "invalid_request"
    | "unauthorized_client"
    | "unsupported_grant_type"
    | (string & {});
  error_description?: string;
}

/** Decoded JWT payload — the claims we actually read. */
export interface TokenClaims {
  /** Auth0 subject — opaque user-id, NOT the username. */
  sub: string;
  /** Standard Auth0 claim mapped to Docker Hub's username field. */
  nickname?: string;
  name?: string;
  email?: string;
  email_verified?: boolean;
  iss: string;
  aud: string | string[];
  exp: number;
  iat: number;
}

// ----- Hub (hub.docker.com) -----

/** A single Personal Access Token as returned by the Hub. */
export interface HubPAT {
  uuid: string;
  client_id: string;
  creator_ip: string | null;
  creator_ua: string | null;
  created_at: string;
  last_used: string | null;
  /** "manual" = user-created, "auto" = desktop-minted. */
  generated_by: string;
  is_active: boolean;
  /** Always "***" in list/inspect; only set on the create response. */
  token: string;
  token_label: string;
  scopes: string[];
  expires_at: string | null;
}

/** Response from GET /v2/access-tokens. */
export interface HubPATListResponse {
  results: HubPAT[];
  active_count: number;
  count: number;
  next: string | null;
  previous: string | null;
}

/** Body for POST /v2/access-tokens. */
export interface CreateHubPATRequest {
  token_label: string;
  scopes: string[];
  /** RFC3339; omit for "no expiry". */
  expires_at?: string;
}

/** Generic Hub API error response. */
export interface HubErrorBody {
  detail?: string;
  message?: string;
  /** Hub-specific error code, e.g. "PAT_NOT_FOUND". */
  code?: string;
}

// ----- Persistent state -----

/** On-disk credential file. Versioned so future migrations are safe. */
export interface StoredCredentials {
  version: 1;
  refresh_token: string;
  username: string;
  saved_at: string; // ISO 8601
  scopes: string[];
  client_id: string;
}

/** In-memory access-token cache (never persisted). */
export interface AccessTokenCache {
  access_token: string;
  /** Unix ms when the token expires. */
  expires_at: number;
}

// ----- Internal helpers -----

/** A function that opens the user's default browser at a URL. */
export type BrowserOpener = (url: string) => Promise<void>;

// ----- Output -----

/** A columnar table row. Keys are column headers, values are strings. */
export type TableRow = Record<string, string>;

export interface OutputOptions {
  /** When true, emit machine-readable JSON instead of a human table. */
  json?: boolean;
}

/** The four scopes a Hub PAT can hold. Validated against this set. */
export const HUB_PAT_SCOPES = [
  "repo:public_read",
  "repo:read",
  "repo:write",
  "repo:admin",
] as const;

export type HubPATScope = (typeof HUB_PAT_SCOPES)[number];

/** Scopes requested from Auth0 during login. Hardcoded per ADR-0006. */
export const LOGIN_SCOPES = ["openid", "offline_access"] as const;

/** Docker Hub's public OAuth client ID. See ADR-0007. */
export const DOCKERHUB_CLIENT_ID = "L4v0dmlNBpYUjGGab0C2JtgTgXr1Qz4d";

/** Auth0 tenant base URL. */
export const TENANT_BASE_URL = "https://login.docker.com";

/** Hub API base URL. */
export const HUB_BASE_URL = "https://hub.docker.com";

/** Audience claim to send to Auth0. */
export const AUTH0_AUDIENCE = "https://hub.docker.com";