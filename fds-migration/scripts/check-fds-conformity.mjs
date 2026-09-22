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
 *   2. Freshness of that bridge against the theme.css the product actually
 *      INSTALLS (the pinned package under node_modules), falling back to a
 *      sibling checkout of the library only when the package is absent. The
 *      verdict names the source it was computed from, in both directions:
 *      compared against two stale copies of each other this check used to
 *      report OK while the product consumed something else.
 *   3. Every "wired" file still imports the generated bridge.
 *   4. No forbidden pattern (a hardcoded value reintroduced into a migrated
 *      zone) matches in a wired file.
 *   5. Every declared library-component usage still holds: the component is
 *      imported from the library (not from MUI), and none of its rendered
 *      instances re-hardcodes a value the component now owns as a prop.
 *      See "Library component usage" below for why this one is not a regex.
 *   6. A state file still on the legacy `paperPattern` field keeps every one of
 *      its guards running, through the same implementations, under its original
 *      check names — so regenerating this script cannot silently drop them.
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

/**
 * Where a freshness verdict may be computed FROM, best source first.
 *
 * This order is the whole point of the check. The INSTALLED package is the copy
 * the product consumes, and its version is pinned in the product's own
 * package.json, so a hash taken from it can make a green verdict mean
 * something. A sibling checkout is on whatever commit the machine happens to
 * hold: when it is stale in the same way the bridge is, the two agree and the
 * guard reports OK while the product ships different values. Measured on
 * OpenCTI, 2026-08-22 — sidecar and sibling both `87f2d00a…`, installed
 * `3c0ef256…`, verdict OK: a whole token release out of date, exit 0.
 *
 * `dist/tokens/theme.css` is a verbatim copy of the library's
 * `src/tokens/theme.css` (the library build copies it unchanged), so it hashes
 * identically to what the bridge generator read.
 *
 * The package may be installed per workspace or hoisted, so every directory
 * from the front workspace up to the product root is a candidate.
 */
function themeCssSources(state) {
  const installedSuffix = path.join(
    "node_modules",
    "@filigran",
    "design-system",
    "packages",
    "filigran-design-system",
    "dist",
    "tokens",
    "theme.css",
  );
  const sources = [];
  let dir = path.join(PRODUCT_ROOT, state.frontDir ?? "");
  for (;;) {
    sources.push({
      authoritative: true,
      kind: "installed package",
      file: path.join(dir, installedSuffix),
    });
    if (dir === PRODUCT_ROOT || path.dirname(dir) === dir) break;
    dir = path.dirname(dir);
  }
  sources.push({
    authoritative: false,
    kind: "sibling checkout",
    file: path.join(
      PRODUCT_ROOT,
      "..",
      "filigran-design-system",
      "packages",
      "filigran-design-system",
      "src",
      "tokens",
      "theme.css",
    ),
  });
  return sources;
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

    // Freshness. The verdict NAMES the source it was computed from, in both
    // directions: a green nobody can trace is a green nobody can read.
    const source = themeCssSources(state).find((candidate) => existsSync(candidate.file));
    if (!source) {
      results.push({
        check: "bridge-freshness",
        file: relPath,
        status: "SKIPPED",
        detail:
          "no theme.css to compare against — the library is neither installed " +
          "under this product nor checked out as a sibling repo. Install the " +
          "dependency (the pinned package carries dist/tokens/theme.css) to make " +
          "this check meaningful.",
      });
      continue;
    }
    const where = `${source.kind} ${path.relative(PRODUCT_ROOT, source.file)}`;
    const provenance = source.authoritative
      ? `compared against the ${where}`
      : `compared against the ${where} — NOT authoritative: this checkout is on ` +
        "whatever commit the machine holds, not on the version this product pins";
    const currentHash = sha256(readFileSync(source.file));
    if (currentHash !== meta.themeCssHash) {
      results.push({
        check: "bridge-freshness",
        file: relPath,
        status: "STALE",
        detail:
          `theme.css changed since this bridge was generated (${provenance}) — run ` +
          `pnpm generate:mui-bridge --product ${state.product ?? "<product>"} ` +
          "--write-to-product again",
      });
    } else {
      results.push({ check: "bridge-freshness", file: relPath, status: "OK", detail: provenance });
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

/* ─── Library component usage (check 5) ────────────────────────────────────
 *
 * WHY THIS IS NOT A `forbiddenPatterns` ENTRY. `forbiddenPatterns` runs a
 * product-authored regex over a whole FILE. That works for what it was built
 * for — "this old hex literal must not come back into a theme file" — and it
 * is the wrong tool for a question about JSX, for three reasons the product
 * pilot ran into directly:
 *
 *   - A component's props span lines. Any regex that reaches across them needs
 *     `[\s\S]*?`, which then happily matches from one element into the NEXT
 *     one's attributes, or out of a `<Paper>` into an unrelated `<Box>`.
 *   - A file-wide match cannot tell WHICH element it hit, so the report says
 *     "this file has a padding somewhere" — true of almost every file, and
 *     useless to act on.
 *   - Comments and strings are indistinguishable from code to a regex. This
 *     repository has already shipped a gate that passed because a rationale
 *     COMMENT contained the exact string it was searching for.
 *
 * So the product declares INTENT (which component, in which files, under
 * which named guards) and the library owns the DETECTION. The scan below is a
 * small lexer, not a pattern: it strips comments, then walks each `<Component`
 * opening tag to ITS OWN closing `>`, tracking quotes, template literals and
 * `{}` nesting. Every rule is then applied to a single element's bounded
 * attribute region — so multiline JSX is not a special case, it is the normal
 * case, and a finding always names one element and one line.
 *
 * Upgrading a guard is a library change that reaches every product on the next
 * `pnpm generate:fds-migration`; the product's own state file only ever names
 * guards, never regexes.
 */

/**
 * Removes `//` and block comments while leaving string and template literals
 * intact, so neither the tag scan nor the attribute rules can be satisfied —
 * or defeated — by commented-out code.
 */
function stripComments(source) {
  let out = "";
  let i = 0;
  let quote = null;
  while (i < source.length) {
    const ch = source[i];
    const next = source[i + 1];
    if (quote) {
      if (ch === "\\") {
        out += ch + (next ?? "");
        i += 2;
        continue;
      }
      if (ch === quote) quote = null;
      out += ch;
      i += 1;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      quote = ch;
      out += ch;
      i += 1;
      continue;
    }
    if (ch === "/" && next === "/") {
      while (i < source.length && source[i] !== "\n") i += 1;
      continue;
    }
    if (ch === "/" && next === "*") {
      i += 2;
      while (i < source.length && !(source[i] === "*" && source[i + 1] === "/")) {
        // Newlines are preserved so reported line numbers stay truthful.
        if (source[i] === "\n") out += "\n";
        i += 1;
      }
      i += 2;
      continue;
    }
    out += ch;
    i += 1;
  }
  return out;
}

/**
 * Every `<Component …>` opening tag in `source`, as `{ attributes, line }`.
 * `attributes` is the raw text between the tag name and THIS tag's own closing
 * `>` — bounded structurally, never by a lookahead.
 */
function scanJsxOpenTags(source, componentName) {
  const tags = [];
  // The character class keeps `<Paper` from matching `<PaperHeader`, and `<`
  // belongs in it: a call site may carry explicit TYPE PARAMETERS,
  // `<Paper<Row> …>`. Without `<` the site is not merely missed, it is
  // reported as DRIFT ("declared, renders nothing") — a confident wrong
  // verdict. Measured on OpenCTI: 9 such sites across 7 files, all invisible.
  const opener = new RegExp(`<${componentName}(?=[\\s/><])`, "g");
  for (const match of source.matchAll(opener)) {
    let attributesStart = match.index + match[0].length;
    // Step over a type-argument list before reading attributes: its own `>`
    // is not the element's, so a scan that stopped at the first one would
    // read `<Row, true>` as the attribute text.
    if (source[attributesStart] === "<") {
      let angle = 0;
      let j = attributesStart;
      for (; j < source.length; j += 1) {
        if (source[j] === "<") angle += 1;
        // `=>` inside a function type is not a closing angle bracket.
        else if (source[j] === ">" && source[j - 1] !== "=") {
          angle -= 1;
          if (angle === 0) {
            j += 1;
            break;
          }
        }
      }
      attributesStart = j;
    }
    let i = attributesStart;
    let depth = 0;
    let quote = null;
    while (i < source.length) {
      const ch = source[i];
      if (quote) {
        if (ch === "\\") {
          i += 2;
          continue;
        }
        if (ch === quote) quote = null;
        i += 1;
        continue;
      }
      if (ch === '"' || ch === "'" || ch === "`") {
        quote = ch;
        i += 1;
        continue;
      }
      if (ch === "{") depth += 1;
      else if (ch === "}") depth -= 1;
      else if (ch === ">" && depth === 0) break;
      i += 1;
    }
    tags.push({
      attributes: source.slice(attributesStart, i),
      line: source.slice(0, match.index).split("\n").length,
    });
  }
  return tags;
}

/**
 * The bounded value of one JSX attribute — `"…"`, `'…'` or `{…}` — or null if
 * the attribute is absent. Same walk as above, so a nested object/call in a
 * braced value cannot end the region early.
 */
function attributeValue(attributes, name) {
  const declaration = new RegExp(`(?:^|\\s)${name}\\s*=\\s*`, "g");
  const match = declaration.exec(attributes);
  if (!match) return null;
  let i = match.index + match[0].length;
  const open = attributes[i];
  if (open === '"' || open === "'") {
    const end = attributes.indexOf(open, i + 1);
    return attributes.slice(i + 1, end === -1 ? attributes.length : end);
  }
  if (open !== "{") return null;
  let depth = 0;
  let quote = null;
  const start = i;
  while (i < attributes.length) {
    const ch = attributes[i];
    if (quote) {
      if (ch === "\\") {
        i += 2;
        continue;
      }
      if (ch === quote) quote = null;
      i += 1;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      quote = ch;
      i += 1;
      continue;
    }
    if (ch === "{") depth += 1;
    else if (ch === "}") {
      depth -= 1;
      if (depth === 0) return attributes.slice(start + 1, i);
    }
    i += 1;
  }
  return attributes.slice(start + 1);
}

/** Tailwind padding utilities, with or without a variant prefix (`md:p-4`). */
const PADDING_CLASS_RE = /(?:^|[\s:])p[xytrbl]?-(?:\d+|px|\[)/;
/** MUI `sx` / inline `style` padding keys, including the `p`/`px` shorthands. */
const PADDING_STYLE_KEY_RE =
  /(?:^|[\s,{'"])(?:p|px|py|pt|pr|pb|pl|padding(?:Top|Right|Bottom|Left|X|Y|Inline|Block)?)\s*:/;

/**
 * The named guards a product may declare. The product's state file names
 * these; it never supplies a pattern. Each returns an array of human-readable
 * findings for ONE declared usage entry.
 */
const LIB_COMPONENT_GUARDS = {
  /**
   * The component still comes from the library, and no longer from MUI. A
   * half-reverted migration reads as migrated (the JSX is unchanged) while
   * rendering the MUI component again — invisible to any JSX-level rule.
   */
  "imported-from-library": ({ component, importFrom, source, file }) => {
    const findings = [];
    const importsLibrary = new RegExp(
      `import\\s*\\{[^}]*\\b${component}\\b[^}]*\\}\\s*from\\s*['"]${importFrom.replace(
        /[.*+?^${}()|[\]\\]/g,
        "\\$&",
      )}['"]`,
    ).test(source);
    if (!importsLibrary) {
      findings.push(
        `${file}: <${component}> is rendered but not imported from "${importFrom}" — the wiring ` +
          `to the library component may have been reverted`,
      );
    }
    const muiImport = new RegExp(
      `import\\s*\\{[^}]*\\b${component}\\b[^}]*\\}\\s*from\\s*['"]@mui/material`,
    ).test(source);
    if (muiImport) {
      findings.push(
        `${file}: <${component}> is imported from @mui/material — the migrated zone has fallen ` +
          `back to the MUI component`,
      );
    }
    return findings;
  },

  /**
   * No rendered instance re-hardcodes padding. Paper owns padding as a typed
   * prop (`padding={0|8|16|24|32}`), and a `className="p-4"` / `sx={{ p: 2 }}`
   * next to it forks the scale back open — which is the whole reason the prop
   * exists. Reported per element, with its line.
   */
  "no-hardcoded-padding": ({ component, source, file }) => {
    const findings = [];
    for (const tag of scanJsxOpenTags(source, component)) {
      const offenders = [];
      const className = attributeValue(tag.attributes, "className");
      if (className && PADDING_CLASS_RE.test(className)) offenders.push("className");
      for (const styleProp of ["sx", "style"]) {
        const value = attributeValue(tag.attributes, styleProp);
        if (value && PADDING_STYLE_KEY_RE.test(value)) offenders.push(styleProp);
      }
      if (offenders.length > 0) {
        findings.push(
          `${file}:${tag.line}: <${component}> sets padding through ${offenders.join(" and ")} — ` +
            `use the \`padding\` prop (0 | 8 | 16 | 24 | 32) so the scale stays one contract. ` +
            `An off-scale value is a deliberate exception: say so in migration-state.json ` +
            `rather than leaving it to read as an oversight.`,
        );
      }
    }
    return findings;
  },
};

function checkLibComponentUsage(state, results) {
  for (const usage of state.libComponentUsage ?? []) {
    const guards = usage.guards ?? [];
    const unknown = guards.filter((name) => !(name in LIB_COMPONENT_GUARDS));
    if (unknown.length > 0) {
      results.push({
        check: "lib-component-usage",
        file: usage.component ?? "<component>",
        status: "INVALID",
        detail:
          `unknown guard(s) ${unknown.join(", ")} in migration-state.json. Available: ` +
          `${Object.keys(LIB_COMPONENT_GUARDS).join(", ")}. Guards are owned by the design ` +
          `system — refresh this script with pnpm generate:fds-migration if you expected a newer one.`,
      });
      continue;
    }
    for (const file of usage.files ?? []) {
      const filePath = path.join(PRODUCT_ROOT, file);
      if (!existsSync(filePath)) {
        results.push({
          check: "lib-component-usage",
          file,
          status: "MISSING",
          detail: "file listed in migration-state.json no longer exists",
        });
        continue;
      }
      const source = stripComments(readFileSync(filePath, "utf8"));
      // A declared file that renders none of the component at all is drift,
      // not a pass: it means the adoption was undone, or the declaration was
      // never true. Reported separately from the guards so the two are not
      // confused.
      if (scanJsxOpenTags(source, usage.component).length === 0) {
        results.push({
          check: "lib-component-usage",
          file,
          status: "DRIFT",
          detail:
            `declared as a <${usage.component}> adoption site but renders no <${usage.component}> ` +
            `at all${usage.reason ? ` — ${usage.reason}` : ""}`,
        });
        continue;
      }
      const findings = guards.flatMap((name) =>
        LIB_COMPONENT_GUARDS[name]({
          component: usage.component,
          importFrom: usage.importFrom ?? "@filigran/design-system",
          source,
          file,
        }),
      );
      if (findings.length === 0) {
        results.push({ check: "lib-component-usage", file, status: "OK" });
      } else {
        for (const detail of findings) {
          results.push({ check: "lib-component-usage", file, status: "FOUND", detail });
        }
      }
    }
  }
}

/**
 * LEGACY MOTIF SHIM — reads a `paperPattern` state file with the generic engine.
 *
 * This exists because of a sequencing hazard that is invisible from the library:
 * the motif field was replaced by `libComponentUsage`, and the script that reads
 * it is GENERATED. A product regenerating its copy before migrating its own
 * state file therefore drops every motif guard AND KEEPS EXITING ZERO — measured
 * on OpenCTI, 2026-08-22: 57 checks to 19, the 38 rows of the Paper motif gone,
 * no error, no warning, nothing to read as a loss.
 *
 * So the migration lives HERE, in the same artifact as the removal: the legacy
 * field keeps running, through the same guard implementations as the new one,
 * and under its original check names so a product's verdict count and diff stay
 * comparable across the regeneration. The notice says what to move.
 *
 * Deliberately NOT reproduced: the new engine's drift check (a declared file
 * that renders none of the component). Adding it here could turn a passing
 * product red on a regeneration, which is the very failure mode this shim
 * exists to prevent. Migrating the state file is what buys that check.
 */
function checkLegacyPaperPattern(state, results) {
  const pattern = state.paperPattern;
  if (!pattern) return;
  results.push({
    check: "lib-component-usage",
    file: "fds-migration/migration-state.json",
    status: "SKIPPED",
    detail:
      "MIGRATION OWED — this state file still declares the legacy `paperPattern` " +
      "field. Its guards are running through the compatibility shim below, so " +
      "nothing is unchecked; move the entries to `libComponentUsage` " +
      "({ component, importFrom, guards, files }) to retire the shim and gain " +
      "the adoption-drift check it deliberately does not reproduce.",
  });
  for (const entry of pattern.files ?? []) {
    const filePath = path.join(PRODUCT_ROOT, entry.file);
    if (!existsSync(filePath)) {
      results.push({
        check: "paper",
        file: entry.file,
        status: "MISSING",
        detail: "declared converted but absent",
      });
      continue;
    }
    const source = stripComments(readFileSync(filePath, "utf8"));
    const guards = entry.guards ?? ["imported-from-library", "no-hardcoded-padding"];
    for (const name of ["imported-from-library", "no-hardcoded-padding"]) {
      const check = `paper:${name}`;
      if (!guards.includes(name)) {
        // A file that legitimately keeps the MUI component declares itself.
        if (name === "imported-from-library" && entry.mixed) {
          results.push({
            check,
            file: entry.file,
            status: "SKIPPED",
            detail: `mixed file — MUI ${pattern.component ?? "Paper"} kept for ${entry.mixed.allowMuiPaperFor}: ${entry.mixed.reason}`,
          });
        }
        continue;
      }
      const findings = LIB_COMPONENT_GUARDS[name]({
        component: pattern.component ?? "Paper",
        importFrom: pattern.importFrom ?? "@filigran/design-system",
        source,
        file: entry.file,
      });
      if (findings.length === 0) results.push({ check, file: entry.file, status: "OK" });
      else
        for (const detail of findings)
          results.push({ check, file: entry.file, status: "FOUND", detail });
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
  checkLibComponentUsage(state, results);
  checkLegacyPaperPattern(state, results);

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
