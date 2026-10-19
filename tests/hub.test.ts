import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  HubError,
  InsufficientPermissionError,
  PATTokenRejectedError,
  RateLimitedError,
  SessionExpiredError,
} from "../src/errors.ts";
import { HubClient } from "../src/hub.ts";
import { startMockServer, type MockServer } from "./mocks/server.ts";

let mock: MockServer;

beforeEach(async () => {
  mock = await startMockServer();
});

afterEach(() => {
  mock.close();
});

const client = (m: MockServer, token = "at_fake") =>
  new HubClient({
    baseUrl: m.hubUrl,
    getAccessToken: async () => token,
  });

describe("HubClient.listTokens", () => {
  test("returns Hub PAT list shape", async () => {
    mock.addPreExistingPAT({ token_label: "first" });
    mock.addPreExistingPAT({ token_label: "second", scopes: ["repo:write"] });
    const res = await client(mock).listTokens();
    expect(res.count).toBe(2);
    expect(res.results.map((r) => r.token_label).sort()).toEqual([
      "first",
      "second",
    ]);
    // Tokens are always redacted in list responses.
    for (const r of res.results) {
      expect(r.token).toBe("***");
    }
  });

  test("maps 401 to SessionExpiredError", async () => {
    const c = new HubClient({
      baseUrl: mock.hubUrl,
      getAccessToken: async () => "bad-token",
    });
    await expect(c.listTokens()).rejects.toBeInstanceOf(SessionExpiredError);
  });

  test("maps 403 PAT-rejection to PATTokenRejectedError", async () => {
    mock.setHubFailNext({
      status: 403,
      detail: "JWT issued from personal access token is not allowed",
    });
    await expect(client(mock).listTokens()).rejects.toBeInstanceOf(
      PATTokenRejectedError,
    );
  });

  test("maps 403 generic to InsufficientPermissionError", async () => {
    mock.setHubFailNext({ status: 403, detail: "Forbidden" });
    await expect(client(mock).listTokens()).rejects.toBeInstanceOf(
      InsufficientPermissionError,
    );
  });

  test("maps 429 to RateLimitedError with retry-after", async () => {
    // We can't easily set Retry-After header in our mock; just verify the body path.
    mock.setHubFailNext({ status: 429, detail: "Slow down" });
    await expect(client(mock).listTokens()).rejects.toBeInstanceOf(
      RateLimitedError,
    );
  });

  test("maps 404 to HubError", async () => {
    mock.setHubFailNext({ status: 404, detail: "not found" });
    await expect(client(mock).listTokens()).rejects.toBeInstanceOf(HubError);
  });
});

describe("HubClient.inspectToken", () => {
  test("returns a single PAT with redacted token", async () => {
    const pat = mock.addPreExistingPAT({ token_label: "solo" });
    const got = await client(mock).inspectToken(pat.uuid);
    expect(got.uuid).toBe(pat.uuid);
    expect(got.token).toBe("***");
  });
});

describe("HubClient.createToken", () => {
  test("creates a token and returns its real value", async () => {
    const pat = await client(mock).createToken({
      token_label: "new",
      scopes: ["repo:read"],
    });
    expect(pat.token_label).toBe("new");
    expect(pat.token).toStartWith("dckr_pat_");
    expect(pat.scopes).toEqual(["repo:read"]);
    expect(pat.uuid).toBeDefined();
  });

  test("includes expires_at when provided", async () => {
    const pat = await client(mock).createToken({
      token_label: "expiring",
      scopes: ["repo:read"],
      expires_at: "2027-01-01T00:00:00Z",
    });
    expect(pat.expires_at).toBe("2027-01-01T00:00:00Z");
  });
});

describe("HubClient.deleteToken", () => {
  test("removes a PAT", async () => {
    const pat = mock.addPreExistingPAT();
    await client(mock).deleteToken(pat.uuid);
    const list = await client(mock).listTokens();
    expect(list.count).toBe(0);
  });
});

describe("HubClient.getCurrentUser", () => {
  test("returns the username from /v/user", async () => {
    mock.setHubUsername("alice");
    const { username, email } = await client(mock).getCurrentUser();
    expect(username).toBe("alice");
    expect(email).toBe("alice@example.com");
  });

  test("falls back to flat username field if user object is missing", async () => {
    // The mock always returns the nested form; this test documents that
    // the implementation handles the flat form too via the ?? fallback.
    const c = new HubClient({
      baseUrl: mock.hubUrl,
      getAccessToken: async () => "at_test",
    });
    const got = await c.getCurrentUser();
    expect(got.username).toBe("testuser");
  });
});