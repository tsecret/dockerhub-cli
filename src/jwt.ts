/**
 * JWT decoding helpers.
 *
 * Used by auth.ts to extract the Docker Hub username from the
 * id_token's `nickname` claim (see ADR-0004). Does NOT verify the
 * signature — we are not authenticating the user; the access token
 * (which has already been issued by Auth0 over TLS) is what we trust.
 * The id_token is only a convenient user-profile payload.
 */

import type { TokenClaims } from "./types.ts";

/**
 * Decode a base64url-encoded string (no padding) to bytes. Works under
 * both Bun and Node 20+.
 */
export function base64UrlDecode(input: string): Uint8Array {
  const padded = input.replace(/-/g, "+").replace(/_/g, "/");
  const padding = padded.length % 4;
  const full = padding ? padded + "=".repeat(4 - padding) : padded;
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(full, "base64"));
  }
  const binary = atob(full);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/**
 * Decode the payload of a JWT (the middle dot-separated segment).
 * Throws on malformed input.
 */
export function decodeJwtPayload<T = unknown>(token: string): T {
  const segments = token.split(".");
  if (segments.length !== 3) {
    throw new Error("Invalid JWT: expected 3 dot-separated segments");
  }
  const payloadSeg = segments[1];
  if (!payloadSeg) {
    throw new Error("Invalid JWT: missing payload segment");
  }
  const bytes = base64UrlDecode(payloadSeg);
  return JSON.parse(new TextDecoder().decode(bytes)) as T;
}

/** Decode the id_token issued by Auth0 and return the standard claims we use. */
export function decodeIdToken(token: string): TokenClaims {
  return decodeJwtPayload<TokenClaims>(token);
}