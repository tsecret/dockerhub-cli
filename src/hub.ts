/**
 * Hub API client.
 *
 * All Hub calls go through HubClient. The client takes a
 * getAccessToken() thunk so it can ask auth.ts for a fresh access
 * token at the moment of the request (auth.ts handles refresh,
 * single-flight locking, and rotation transparently).
 *
 * Routes:
 *   GET    /v2/access-tokens          list
 *   GET    /v2/access-tokens/{uuid}   inspect
 *   POST   /v2/access-tokens          create
 *   DELETE /v2/access-tokens/{uuid}   delete
 */

import {
  CLIError,
  ExitCode,
  fromHubError,
  PATTokenRejectedError,
  RateLimitedError,
} from "./errors.ts";
import { parseHubErrorBody } from "./shapes.ts";
import {
  HUB_BASE_URL,
  HUB_PAT_SCOPES,
  type CreateHubPATRequest,
  type HubPAT,
  type HubPATListResponse,
} from "./types.ts";

export interface HubClientOptions {
  baseUrl?: string;
  fetchImpl?: typeof fetch;
  /** Returns a fresh bearer token. Called once per request. */
  getAccessToken: () => Promise<string>;
}

export class HubClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly getAccessToken: () => Promise<string>;

  constructor(opts: HubClientOptions) {
    this.baseUrl = opts.baseUrl ?? HUB_BASE_URL;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.getAccessToken = opts.getAccessToken;
  }

  private async request(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<Response> {
    const accessToken = await this.getAccessToken();
    const headers: Record<string, string> = {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/json",
    };
    const init: RequestInit = { method, headers };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    return await this.fetchImpl(`${this.baseUrl}${path}`, init);
  }

  private async handleError(res: Response): Promise<never> {
    let parsed: ReturnType<typeof parseHubErrorBody> = {};
    try {
      parsed = parseHubErrorBody(await res.json());
    } catch {
      // Body wasn't JSON (e.g. an HTML 502 page from a load balancer).
      // Treat as empty so the fallback messages in fromHubError apply.
    }

    // Hub-specific: "token issued from personal access token is not allowed"
    const detail = parsed.detail ?? "";
    if (detail.includes("issued from personal access token")) {
      throw new PATTokenRejectedError(detail);
    }

    if (res.status === 429) {
      const ra = res.headers.get("Retry-After");
      const secs = ra ? parseInt(ra, 10) : undefined;
      throw new RateLimitedError(
        Number.isFinite(secs) ? (secs as number) : undefined,
        parsed.detail ?? parsed.message ?? "Rate limited by Docker Hub.",
      );
    }

    throw fromHubError(res.status, parsed);
  }

  /** GET /v2/access-tokens */
  async listTokens(): Promise<HubPATListResponse> {
    const res = await this.request("GET", "/v2/access-tokens");
    if (!res.ok) await this.handleError(res);
    return (await res.json()) as HubPATListResponse;
  }

  /** GET /v2/access-tokens/{uuid} */
  async inspectToken(uuid: string): Promise<HubPAT> {
    const res = await this.request("GET", `/v2/access-tokens/${uuid}`);
    if (!res.ok) await this.handleError(res);
    return (await res.json()) as HubPAT;
  }

  /**
   * GET /v2/user — returns the authenticated user's profile.
   *
   * This is the canonical source of the Docker Hub username. The
   * id_token's `sub` claim is an opaque Auth0 user id (e.g. `auth0|<uuid>`)
   * that is not useful as a display name; `nickname` may be absent for
   * some login methods. The Hub API always returns the real username.
   */
  async getCurrentUser(): Promise<{ username: string; email?: string }> {
    const res = await this.request("GET", "/v2/user");
    if (!res.ok) await this.handleError(res);
    const body = (await res.json()) as {
      user?: { username?: string; email?: string };
      username?: string;
      email?: string;
    };
    const username = body.user?.username ?? body.username;
    if (!username) {
      throw new CLIError(
        "Could not determine username from /v2/user response.",
        {
          exitCode: ExitCode.HubError,
          detail: JSON.stringify(body).slice(0, 200),
        },
      );
    }
    return {
      username,
      email: body.user?.email ?? body.email,
    };
  }

  /** POST /v2/access-tokens */
  async createToken(req: CreateHubPATRequest): Promise<HubPAT> {
    const res = await this.request("POST", "/v2/access-tokens", req);
    if (!res.ok) await this.handleError(res);
    return (await res.json()) as HubPAT;
  }

  /** DELETE /v2/access-tokens/{uuid} */
  async deleteToken(uuid: string): Promise<void> {
    const res = await this.request("DELETE", `/v2/access-tokens/${uuid}`);
    if (!res.ok) await this.handleError(res);
    // 204 No Content on success.
  }
}

/**
 * Validate that all scopes in a list are known Hub PAT scopes. Throws
 * UsageError on the first unknown value.
 */
export function validateScopes(scopes: readonly string[]): void {
  for (const s of scopes) {
    if (!(HUB_PAT_SCOPES as readonly string[]).includes(s)) {
      throw new CLIError(
        `Unknown scope: ${s}. Valid scopes: ${HUB_PAT_SCOPES.join(", ")}`,
        {
          exitCode: ExitCode.Usage,
          hint: "Hub PAT scopes are account-wide: repo:public_read, repo:read, repo:write, repo:admin.",
        },
      );
    }
  }
}