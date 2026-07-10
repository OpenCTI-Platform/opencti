#!/usr/bin/env node
/**
 * fds-migration conformity check — GENERATED TEMPLATE, copied verbatim from
 * filigran-design-system/scripts/fds-migration-templates/check-fds-conformity.mjs
 * by scripts/generate-fds-migration.ts. Do not hand-edit here; fix the
 * template upstream and re-run `pnpm generate:fds-migration --product <name>`
 * (filigran-design-system repo) to refresh every product's copy.
 *
 * Zero dependencies (plain Node, .mjs so it's ESM regardless of this
 * product's own package.json "type") — runs with whatever toolchain the
 * product already has, no pnpm/tsx requirement.
 *
 * Verifies, driven entirely by migration-state.json (never hardcoded here):
 *   1. The generated bridge file(s) haven't been hand-edited (sha256 vs the
 *      sidecar .meta.json written at generation time).
 *   2. Best-effort freshness vs the design system's current theme.css, IF
 *      filigran-design-system is checked out as a sibling repo — skipped
 *      otherwise, so this still works standalone in the product's own CI.
 *   3. Every "wired" file still imports the generated bridge.
 *   4. No forbidden pattern (a hardcoded value reintroduced into a migrated
 *      zone) matches in a wired file.
 *
 * The check LISTS every issue it finds (this file), it does not decide what
 * to do about them — that's the agent's job, per the reconciliation loop in
 * fds-migration/AGENTS.md.
 *
 * Usage: node fds-migration/scripts/check-fds-conformity.mjs [--warn]
 *   --warn: always exit 0 (report only) — for non-blocking product CI.
 */
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FDS_MIGRATION_DIR = path.resolve(__dirname, "..");
const PRODUCT_ROOT = path.resolve(FDS_MIGRATION_DIR, "..");
const STATE_PATH = path.join(FDS_MIGRATION_DIR, "migration-state.json");
const REPORT_PATH = path.join(FDS_MIGRATION_DIR, "reports", "conformity-latest.json");

const warnMode = process.argv.includes("--warn");

function sha256(content) {
  return `sha256:${createHash("sha256").update(content).digest("hex")}`;
}

function loadJson(filePath) {
  return JSON.parse(readFileSync(filePath, "utf8"));
}

function checkBridgeFiles(state, results) {
  for (const relPath of state.generatedBridgeFiles ?? []) {
    const tsPath = path.join(PRODUCT_ROOT, state.frontDir ?? "", relPath);
    const metaPath = tsPath.replace(/\.ts$/, ".meta.json");

    if (!existsSync(tsPath) || !existsSync(metaPath)) {
      results.push({
        check: "bridge-integrity",
        file: relPath,
        status: "MISSING",
        detail: "generated file or sidecar .meta.json not found — run pnpm generate:mui-bridge",
      });
      continue;
    }

    const content = readFileSync(tsPath, "utf8");
    const meta = loadJson(metaPath);
    const actualHash = sha256(content);
    if (actualHash !== meta.tsFileSha256) {
      results.push({
        check: "bridge-integrity",
        file: relPath,
        status: "MISMATCH",
        detail:
          "file content doesn't match the sha256 recorded at generation time — was it " +
          "hand-edited? Regenerate instead: pnpm generate:mui-bridge --product " +
          `${state.product ?? "<product>"} --write-to-product`,
      });
    } else {
      results.push({ check: "bridge-integrity", file: relPath, status: "OK" });
    }

    const libThemeCss = path.join(
      PRODUCT_ROOT,
      "..",
      "filigran-design-system",
      "packages",
      "filigran-design-system",
      "src",
      "tokens",
      "theme.css",
    );
    if (existsSync(libThemeCss)) {
      const currentHash = sha256(readFileSync(libThemeCss));
      if (currentHash !== meta.themeCssHash) {
        results.push({
          check: "bridge-freshness",
          file: relPath,
          status: "STALE",
          detail:
            "theme.css changed since this bridge was generated — run " +
            `pnpm generate:mui-bridge --product ${state.product ?? "<product>"} ` +
            "--write-to-product again",
        });
      } else {
        results.push({ check: "bridge-freshness", file: relPath, status: "OK" });
      }
    } else {
      results.push({
        check: "bridge-freshness",
        file: relPath,
        status: "SKIPPED",
        detail:
          "filigran-design-system not checked out as a sibling repo — can't compare theme.css",
      });
    }
  }
}

function checkWiring(state, results) {
  for (const wired of state.wiredFiles ?? []) {
    const filePath = path.join(PRODUCT_ROOT, wired.file);
    if (!existsSync(filePath)) {
      results.push({
        check: "wiring",
        file: wired.file,
        status: "MISSING",
        detail: "file listed in migration-state.json no longer exists",
      });
      continue;
    }
    const content = readFileSync(filePath, "utf8");
    if (!content.includes(wired.mustImport)) {
      results.push({
        check: "wiring",
        file: wired.file,
        status: "DRIFT",
        detail: `expected to find "${wired.mustImport}" — the wiring to the generated bridge may have been reverted`,
      });
    } else {
      results.push({ check: "wiring", file: wired.file, status: "OK" });
    }
  }
}

function checkForbiddenPatterns(state, results) {
  for (const forbidden of state.forbiddenPatterns ?? []) {
    const filePath = path.join(PRODUCT_ROOT, forbidden.file);
    if (!existsSync(filePath)) continue;
    const content = readFileSync(filePath, "utf8");
    let regex;
    try {
      regex = new RegExp(forbidden.pattern);
    } catch (err) {
      results.push({
        check: "forbidden-pattern",
        file: forbidden.file,
        status: "INVALID",
        detail: `invalid regex "${forbidden.pattern}" in migration-state.json: ${err.message}`,
      });
      continue;
    }
    if (regex.test(content)) {
      results.push({
        check: "forbidden-pattern",
        file: forbidden.file,
        status: "FOUND",
        detail: forbidden.reason ?? `pattern /${forbidden.pattern}/ matched`,
      });
    } else {
      results.push({ check: "forbidden-pattern", file: forbidden.file, status: "OK" });
    }
  }
}

function main() {
  if (!existsSync(STATE_PATH)) {
    console.error(
      `fds-conformity: missing ${path.relative(PRODUCT_ROOT, STATE_PATH)} — run ` +
        "pnpm generate:fds-migration first (filigran-design-system repo).",
    );
    process.exit(1);
  }

  const state = loadJson(STATE_PATH);
  const results = [];
  checkBridgeFiles(state, results);
  checkWiring(state, results);
  checkForbiddenPatterns(state, results);

  const failing = results.filter((r) => !["OK", "SKIPPED"].includes(r.status));

  console.log(`fds-migration conformity — ${results.length} checks, ${failing.length} issue(s)`);
  for (const r of results) {
    const marker = r.status === "OK" ? "✅" : r.status === "SKIPPED" ? "⏭️ " : "❌";
    console.log(`${marker} [${r.check}] ${r.file}: ${r.status}${r.detail ? " — " + r.detail : ""}`);
  }

  mkdirSync(path.dirname(REPORT_PATH), { recursive: true });
  writeFileSync(
    REPORT_PATH,
    JSON.stringify({ generatedAt: new Date().toISOString(), results }, null, 2) + "\n",
  );
  console.log(`\nReport: ${path.relative(PRODUCT_ROOT, REPORT_PATH)}`);

  if (failing.length > 0 && !warnMode) process.exit(1);
  if (failing.length > 0 && warnMode) {
    console.log("(--warn mode: exiting 0 despite issues above — non-blocking CI use)");
  }
}

main();
