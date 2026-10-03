#!/usr/bin/env node
/**
 * MUI regression gate.
 *
 * Fails when NEW code introduces a MUI (or legacy filigran-ui) import whose
 * design-system replacement is already in service in THIS product.
 *
 * Scope is deliberately narrow, and that narrowness is what makes the gate
 * safe to make blocking on day one:
 *
 *   - Only symbols a file did NOT already import on the merge base are read,
 *     compared per file, base version against head version. Every import that
 *     already exists keeps working and is never reported, even when its line
 *     is edited. The ~1000 files importing MUI today are untouched by
 *     construction. Reading added LINES instead re-reported every symbol that
 *     merely survived an edit — including lines that removed MUI imports.
 *   - Only the 14 components the library has actually finished AND that are
 *     already rendering in this product are enforced. The list is generated,
 *     not typed here: fds-migration/mui-regression-policy.generated.json,
 *     emitted by `pnpm generate:mui-regression-policy --product opencti` in
 *     the filigran-design-system repo.
 *   - A component the library has not settled yet (`held`) or that has no MUI
 *     counterpart at all (`notGatable`) is never enforced. Both lists are in
 *     the policy file and printed by --explain.
 *
 * Escape hatch: put `fds:keep-mui <reason>` in a comment on the import line or
 * on the line directly above it. The reason is required. Every use is a
 * documented, greppable hold — `--list-holds` prints them.
 *
 * Usage:
 *   node fds-migration/scripts/check-mui-regression.mjs [--base <ref>] [--explain] [--list-holds]
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, "..", "..");
const POLICY_PATH = path.join(REPO_ROOT, "fds-migration", "mui-regression-policy.generated.json");
const DEFAULT_BASE = "origin/design-system/current";
const KEEP_MARKER = "fds:keep-mui";
const SOURCE_RE = /^@mui\/|^@filigran\/ui(\/|$)/;
const CODE_EXT = new Set([".ts", ".tsx", ".js", ".jsx"]);

function arg(name, fallback = null) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : fallback;
}
const has = (name) => process.argv.includes(name);

function git(args) {
  return execFileSync("git", args, { cwd: REPO_ROOT, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
}

/** Named (`import { A, B } from 'x'`) and default (`import A from 'x/A'`) forms. */
function importedSymbols(line) {
  const from = line.match(/from\s+['"]([^'"]+)['"]/);
  if (!from || !SOURCE_RE.test(from[1])) return [];
  const source = from[1];
  const named = line.match(/import\s*(?:type\s*)?\{([^}]*)\}/);
  if (named) {
    return named[1]
      .split(",")
      .map((s) => s.trim().split(/\s+as\s+/)[0].trim())
      .filter(Boolean);
  }
  const dflt = line.match(/import\s+(?:type\s+)?([A-Z][A-Za-z0-9_]*)\s+from/);
  // A default import carries no symbol name at the source, so the module's own
  // last path segment is the component: '@mui/material/Button' -> Button.
  if (dflt) return [source.split("/").pop()];
  return [];
}

function mergeBase(base) {
  try {
    return git(["merge-base", "HEAD", base]).trim();
  } catch {
    return null;
  }
}

/** Watched-source symbols a file imports, mapped to the line each sits on. */
function importsIn(source) {
  const found = new Map();
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i += 1) {
    for (const symbol of importedSymbols(lines[i])) {
      if (!found.has(symbol)) found.set(symbol, i + 1);
    }
  }
  return found;
}

/**
 * Code files touched against the base, each with the path it had there.
 * `-M` so a renamed file is compared to its old path instead of counting as
 * new, which would report every import it carries over.
 */
function changedFiles(from) {
  const out = [];
  const raw = git(["diff", "-M", "--name-status", "-z", `${from}...HEAD`]).split("\0");
  for (let i = 0; i < raw.length; i += 1) {
    const status = raw[i];
    if (!status) continue;
    if (status.startsWith("R")) {
      const [before, after] = [raw[i + 1], raw[i + 2]];
      i += 2;
      if (CODE_EXT.has(path.extname(after ?? ""))) out.push({ file: after, basePath: before });
    } else if (status.startsWith("D")) {
      i += 1;
    } else {
      const file = raw[i + 1];
      i += 1;
      if (CODE_EXT.has(path.extname(file ?? ""))) {
        out.push({ file, basePath: status.startsWith("A") ? null : file });
      }
    }
  }
  return out;
}

function fileAt(ref, file) {
  try {
    return git(["show", `${ref}:${file}`]);
  } catch {
    return null;
  }
}

function heldOnLine(lines, lineNo) {
  const text = lines[lineNo - 1] ?? "";
  if (text.includes(KEEP_MARKER)) return text.slice(text.indexOf(KEEP_MARKER)).trim();
  const above = lines[lineNo - 2] ?? "";
  return above.includes(KEEP_MARKER) ? above.slice(above.indexOf(KEEP_MARKER)).trim() : null;
}

function main() {
  if (!fs.existsSync(POLICY_PATH)) {
    console.error(`Policy file missing: ${path.relative(REPO_ROOT, POLICY_PATH)}`);
    console.error("Regenerate it from the filigran-design-system repo.");
    process.exit(1);
  }
  const policy = JSON.parse(fs.readFileSync(POLICY_PATH, "utf8"));

  if (has("--explain")) {
    console.log(`Policy generated from ROADMAP.json of ${policy.roadmapLastUpdated}\n`);
    const byComponent = {};
    for (const [sym, comp] of Object.entries(policy.enforced)) (byComponent[comp] ??= []).push(sym);
    console.log(`ENFORCED (${Object.keys(byComponent).length} components, ${Object.keys(policy.enforced).length} symbols):`);
    for (const [c, s] of Object.entries(byComponent)) console.log(`  ${c.padEnd(14)} ${s.join(", ")}`);
    console.log(`\nHELD (${policy.held.length}) — in service, library API not settled:`);
    for (const h of policy.held) console.log(`  ${h.component.padEnd(14)} lib status: ${h.libStatus}`);
    console.log(`\nNOT GATABLE (${policy.notGatable.length}) — no MUI counterpart exists:`);
    for (const n of policy.notGatable) console.log(`  ${n.component}`);
    return;
  }

  if (has("--list-holds")) {
    const hits = git(["grep", "-n", KEEP_MARKER, "--", "*.ts", "*.tsx", "*.js", "*.jsx"]).trim();
    console.log(hits || `No ${KEEP_MARKER} marker in the tree.`);
    return;
  }

  const base = arg("--base", DEFAULT_BASE);
  const from = mergeBase(base);
  if (!from) {
    console.error(`Cannot resolve a merge base against "${base}".`);
    console.error("Fetch the base branch first, or pass --base <ref>.");
    process.exit(1);
  }

  const findings = [];
  let held = 0;
  for (const { file, basePath } of changedFiles(from)) {
    // The working tree first, so a `fds:keep-mui` added but not yet committed
    // is honoured locally; CI checks out HEAD, where the two are the same.
    const onDisk = path.join(REPO_ROOT, file);
    const headSource = fs.existsSync(onDisk) ? fs.readFileSync(onDisk, "utf8") : fileAt("HEAD", file);
    if (headSource === null) continue;
    const baseSource = basePath ? fileAt(from, basePath) : null;
    const alreadyThere = baseSource === null ? new Set() : new Set(importsIn(baseSource).keys());
    const lines = headSource.split("\n");
    for (const [symbol, line] of importsIn(headSource)) {
      if (alreadyThere.has(symbol)) continue;
      const replacement = policy.enforced[symbol];
      if (!replacement) continue;
      const hold = heldOnLine(lines, line);
      if (hold) {
        held += 1;
        continue;
      }
      findings.push({ file, line, symbol, replacement });
    }
  }
  findings.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);

  const scope = `${from.slice(0, 9)}...HEAD`;
  if (findings.length === 0) {
    console.log(`MUI regression gate: PASS (${scope})`);
    console.log(
      `  ${Object.keys(policy.enforced).length} symbols watched, ` +
        `${policy.summary.held} component(s) held, ${policy.summary.notGatable} not gatable` +
        (held ? `, ${held} occurrence(s) exempted by ${KEEP_MARKER}` : ""),
    );
    return;
  }

  console.error(`MUI regression gate: FAIL — ${findings.length} new import(s) (${scope})\n`);
  for (const f of findings) {
    console.error(`  ${f.file}:${f.line}`);
    console.error(`    imports MUI \`${f.symbol}\`; this product already renders the design system's \`${f.replacement}\`.`);
  }
  console.error(`
Fix one of these ways:
  - import ${findings[0].replacement} from '@filigran/design-system' instead (preferred);
  - if the library component genuinely cannot serve this case, add
    \`// ${KEEP_MARKER} <reason>\` above the import and record the gap in the
    library's ROADMAP.json or process/AI-BACKLOG.md.

The full policy, including what is deliberately NOT enforced:
  node fds-migration/scripts/check-mui-regression.mjs --explain`);
  process.exit(1);
}

main();
