/**
 * Output formatting for human and --json modes.
 *
 * All read commands support --json. Write commands (token create)
 * print the sensitive value (the new PAT) to stdout once and a warning
 * to stderr. See ADR-0001 and the spec's "token output policy".
 */

import type { HubPAT, OutputOptions, TableRow } from "./types.ts";

/** Stringify with optional pretty-print. */
export function toJSON<T>(value: T, opts: OutputOptions = {}): string {
  return JSON.stringify(value, null, opts.json ? 2 : 0);
}

/** Convert a Hub PAT into a single line of fixed column order. */
export function patToTableRow(pat: HubPAT): TableRow {
  return {
    LABEL: pat.token_label,
    UUID: pat.uuid,
    SCOPES: pat.scopes.join(","),
    STATUS: pat.is_active ? "active" : "inactive",
    CREATED: pat.created_at,
    "LAST USED": pat.last_used ?? "never",
    EXPIRES: pat.expires_at ?? "never",
    SOURCE: pat.generated_by,
  };
}

/**
 * Render a list of rows as a fixed-width table. Column order is the
 * first-seen key order (insertion order on the Set). Empty input
 * returns "(no tokens)".
 */
export function formatTable(rows: TableRow[]): string {
  if (rows.length === 0) return "(no tokens)";
  const headerSet = new Set<string>();
  for (const row of rows) {
    for (const k of Object.keys(row)) headerSet.add(k);
  }
  const headers = Array.from(headerSet);
  const widths = headers.map((h) => {
    const values = rows.map((r) => String(r[h] ?? ""));
    return Math.max(h.length, ...values.map((v) => v.length));
  });
  const formatRow = (cells: string[]) =>
    cells.map((c, i) => c.padEnd(widths[i] ?? 0)).join("  ");
  const lines: string[] = [];
  lines.push(formatRow(headers));
  lines.push(formatRow(widths.map((w) => "-".repeat(w))));
  for (const row of rows) {
    lines.push(formatRow(headers.map((h) => String(row[h] ?? ""))));
  }
  return lines.join("\n");
}

/** Format a list of PATs as a table or JSON. */
export function formatPATList(pats: HubPAT[], opts: OutputOptions = {}): string {
  if (opts.json) return toJSON(pats, opts);
  return formatTable(pats.map(patToTableRow));
}

/** Format a single PAT as labeled key/value lines or JSON. */
export function formatPAT(pat: HubPAT, opts: OutputOptions = {}): string {
  if (opts.json) return toJSON(pat, opts);
  return [
    `Label:     ${pat.token_label}`,
    `UUID:      ${pat.uuid}`,
    `Scopes:    ${pat.scopes.join(", ")}`,
    `Status:    ${pat.is_active ? "active" : "inactive"}`,
    `Created:   ${pat.created_at}`,
    `Last used: ${pat.last_used ?? "never"}`,
    `Expires:   ${pat.expires_at ?? "never"}`,
    `Source:    ${pat.generated_by}`,
  ].join("\n");
}

/**
 * Render the result of `dockerhub token create`. Returns stdout
 * (token + structured metadata as comments) and stderr (warning).
 * The caller prints them to their respective streams.
 */
export function formatCreatedPAT(pat: HubPAT): { stdout: string; stderr: string } {
  const stdout = [
    pat.token,
    `# Label:   ${pat.token_label}`,
    `# UUID:    ${pat.uuid}`,
    `# Scopes:  ${pat.scopes.join(", ")}`,
    `# Expires: ${pat.expires_at ?? "never"}`,
  ].join("\n");
  const stderr = [
    "",
    "WARNING: This token will not be shown again.",
    "         Store it now (e.g. in a password manager).",
    `         Inspect with: dockerhub token inspect ${pat.uuid}`,
    `         Revoke with:   dockerhub token delete ${pat.uuid}`,
    "",
  ].join("\n");
  return { stdout, stderr };
}