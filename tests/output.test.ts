import { describe, expect, test } from "bun:test";

import {
  formatCreatedPAT,
  formatPAT,
  formatPATList,
  formatTable,
  patToTableRow,
  toJSON,
} from "../src/output.ts";
import type { HubPAT } from "../src/types.ts";

const sample: HubPAT = {
  uuid: "abc-123",
  client_id: "HUB",
  creator_ip: "127.0.0.1",
  creator_ua: "test",
  created_at: "2026-10-19T00:00:00Z",
  last_used: "2026-10-19T01:00:00Z",
  generated_by: "manual",
  is_active: true,
  token: "dckr_pat_xyz",
  token_label: "alpha",
  scopes: ["repo:read", "repo:write"],
  expires_at: null,
};

describe("toJSON", () => {
  test("emits pretty-printed JSON when opts.json", () => {
    expect(toJSON({ a: 1 }, { json: true })).toBe('{\n  "a": 1\n}');
  });
  test("emits single-line JSON when not opts.json", () => {
    expect(toJSON({ a: 1 })).toBe('{"a":1}');
  });
});

describe("patToTableRow", () => {
  test("maps PAT to flat key/value row", () => {
    const row = patToTableRow(sample);
    expect(row.LABEL).toBe("alpha");
    expect(row.UUID).toBe("abc-123");
    expect(row.SCOPES).toBe("repo:read,repo:write");
    expect(row.STATUS).toBe("active");
    expect(row.EXPIRES).toBe("never");
    expect(row["LAST USED"]).toBe("2026-10-19T01:00:00Z");
  });

  test("shows inactive status when is_active is false", () => {
    const row = patToTableRow({ ...sample, is_active: false });
    expect(row.STATUS).toBe("inactive");
  });

  test("shows 'never' when last_used is null", () => {
    const row = patToTableRow({ ...sample, last_used: null });
    expect(row["LAST USED"]).toBe("never");
  });
});

describe("formatTable", () => {
  test("emits header + separator + rows", () => {
    const out = formatTable([patToTableRow(sample)]);
    const lines = out.split("\n");
    expect(lines.length).toBeGreaterThan(2);
    expect(lines[0]).toContain("LABEL");
    expect(lines[1]).toMatch(/^-+/);
    expect(lines[2]).toContain("alpha");
  });

  test("emits '(no tokens)' for empty input", () => {
    expect(formatTable([])).toBe("(no tokens)");
  });
});

describe("formatPATList", () => {
  test("JSON mode emits array", () => {
    const out = formatPATList([sample], { json: true });
    const parsed = JSON.parse(out) as HubPAT[];
    expect(parsed).toHaveLength(1);
    expect(parsed[0]?.token_label).toBe("alpha");
  });

  test("human mode emits a table", () => {
    const out = formatPATList([sample]);
    expect(out).toContain("alpha");
  });
});

describe("formatPAT", () => {
  test("JSON mode emits single object", () => {
    const out = formatPAT(sample, { json: true });
    expect(JSON.parse(out).token_label).toBe("alpha");
  });

  test("human mode includes key fields", () => {
    const out = formatPAT(sample);
    expect(out).toContain("Label:");
    expect(out).toContain("alpha");
    expect(out).toContain("Scopes:");
    expect(out).toContain("repo:read, repo:write");
  });
});

describe("formatCreatedPAT", () => {
  test("stdout contains the token and metadata as comments", () => {
    const { stdout } = formatCreatedPAT(sample);
    expect(stdout).toContain(sample.token);
    expect(stdout).toContain(`# Label:   ${sample.token_label}`);
    expect(stdout).toContain(`# UUID:    ${sample.uuid}`);
  });

  test("stderr contains a warning and follow-up commands", () => {
    const { stderr } = formatCreatedPAT(sample);
    expect(stderr).toContain("WARNING");
    expect(stderr).toContain(`dockerhub token inspect ${sample.uuid}`);
    expect(stderr).toContain(`dockerhub token delete ${sample.uuid}`);
  });
});