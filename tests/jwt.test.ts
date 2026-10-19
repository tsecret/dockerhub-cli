import { describe, expect, test } from "bun:test";
import { base64UrlDecode, decodeIdToken, decodeJwtPayload } from "../src/jwt.ts";

describe("base64UrlDecode", () => {
  test("decodes standard base64url input", () => {
    // "hello" base64url
    const out = base64UrlDecode("aGVsbG8");
    expect(new TextDecoder().decode(out)).toBe("hello");
  });

  test("handles url-safe chars (- and _)", () => {
    // ">>?" → "Pj4_" in base64url, "Pj4/" in standard base64
    const out = base64UrlDecode("Pj4_");
    expect(new TextDecoder().decode(out)).toBe(">>?");
  });

  test("pads when length is not %4", () => {
    // "ab" → "YWI" (no padding) base64url → standard "YWI=" padded
    const out = base64UrlDecode("YWI");
    expect(new TextDecoder().decode(out)).toBe("ab");
  });

  test("decodes raw bytes", () => {
    const out = base64UrlDecode("AQID"); // bytes 1, 2, 3
    expect(Array.from(out)).toEqual([1, 2, 3]);
  });
});

describe("decodeJwtPayload", () => {
  test("returns the middle segment as JSON", () => {
    const header = btoa(JSON.stringify({ alg: "HS256" }));
    const payload = btoa(JSON.stringify({ sub: "abc", n: 1 }));
    const sig = "sig";
    const token = `${header}.${payload}.${sig}`;
    const decoded = decodeJwtPayload<{ sub: string; n: number }>(token);
    expect(decoded.sub).toBe("abc");
    expect(decoded.n).toBe(1);
  });

  test("throws on non-3-segment input", () => {
    expect(() => decodeJwtPayload("a.b")).toThrow(/3 dot-separated/);
  });

  test("throws on invalid base64", () => {
    expect(() => decodeJwtPayload("a.!!!.b")).toThrow();
  });
});

describe("decodeIdToken", () => {
  test("returns Auth0-style claims", () => {
    const header = btoa(JSON.stringify({ alg: "HS256" }));
    const payload = btoa(
      JSON.stringify({
        sub: "auth0|123",
        nickname: "alice",
        email: "alice@example.com",
        iss: "https://login.docker.com/",
        aud: "https://hub.docker.com",
        exp: 1234567890,
        iat: 1234567000,
      }),
    );
    const token = `${header}.${payload}.sig`;
    const claims = decodeIdToken(token);
    expect(claims.nickname).toBe("alice");
    expect(claims.sub).toBe("auth0|123");
    expect(claims.exp).toBe(1234567890);
  });
});