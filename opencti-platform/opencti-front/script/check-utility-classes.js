#!/usr/bin/env node
/**
 * Fails on any utility class written in product code that does not exist in the
 * CSS the app actually loads.
 *
 * Why this gate exists. The front end ships no Tailwind of its own — no config,
 * no dependency, no plugin, no `@tailwind` directive — so every utility class
 * comes from `@filigran/design-system`'s pre-compiled `dist/index.css`, which is
 * built by scanning the LIBRARY's sources. A class the library does not itself
 * use is simply absent, and writing it here does nothing at all: no margin, no
 * build error, no runtime error. Measured 2026-08-28: 27 uses of `mt-5` across
 * 24 files and 1 of `mt-4` were inert, some for weeks.
 *
 * The library now publishes its spacing scale deliberately, but the failure mode
 * is permanent — any class outside what the delivered CSS carries is silently
 * dead. This is the check that makes it loud.
 *
 * Usage: node scripts/check-utility-classes.js
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SRC = path.join(ROOT, 'src');

/** Every stylesheet the running app loads, in front.tsx order. */
function stylesheets() {
  const out = [];
  const lib = path.join(
    ROOT, 'node_modules', '@filigran', 'design-system',
    'packages', 'filigran-design-system', 'dist', 'index.css',
  );
  const flat = path.join(ROOT, 'node_modules', '@filigran', 'design-system', 'dist', 'index.css');
  for (const p of [lib, flat]) if (fs.existsSync(p)) { out.push(p); break; }
  const staticDir = path.join(SRC, 'static', 'css');
  if (fs.existsSync(staticDir)) {
    for (const f of fs.readdirSync(staticDir)) if (f.endsWith('.css')) out.push(path.join(staticDir, f));
  }
  return out;
}

/** Class names defined by those stylesheets, unescaped. */
function definedClasses(files) {
  const set = new Set();
  for (const f of files) {
    const css = fs.readFileSync(f, 'utf8');
    for (const m of css.matchAll(/\.((?:[A-Za-z0-9_-]|\\.)+)/g)) {
      set.add(m[1].replace(/\\(.)/g, '$1'));
    }
  }
  return set;
}

/**
 * A token is only treated as a utility if it looks like one. Product code also
 * carries BEM-ish and library-agnostic class names, and flagging those would be
 * noise rather than signal.
 */
const UTILITY = /^-?(?:[a-z]+:)*(?:m|p)[tblrxy]?-\d+(?:\.\d+)?$/;

function sourceFiles(dir, acc = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) { if (!/__generated__|node_modules/.test(p)) sourceFiles(p, acc); }
    else if (/\.(tsx|jsx)$/.test(p)) acc.push(p);
  }
  return acc;
}

function main() {
  const sheets = stylesheets();
  if (sheets.length === 0) {
    console.error('No stylesheet found — is @filigran/design-system installed?');
    process.exit(1);
  }
  const defined = definedClasses(sheets);
  const dead = [];
  for (const file of sourceFiles(SRC)) {
    const src = fs.readFileSync(file, 'utf8');
    if (!/className/.test(src)) continue;
    const lines = src.split('\n');
    lines.forEach((line, i) => {
      for (const m of line.matchAll(/className=(?:"([^"]*)"|\{`([^`]*)`\})/g)) {
        const value = m[1] ?? m[2] ?? '';
        for (const token of value.split(/\s+/)) {
          if (!token || token.includes('${')) continue;
          if (!UTILITY.test(token)) continue;
          if (!defined.has(token)) {
            dead.push({ file: path.relative(ROOT, file), line: i + 1, token });
          }
        }
      }
    });
  }

  console.log(`Stylesheets checked (${sheets.length}):`);
  for (const s of sheets) console.log(`  ${path.relative(ROOT, s)}`);
  console.log(`Spacing utilities defined: ${[...defined].filter((c) => UTILITY.test(c)).length}`);

  if (dead.length === 0) {
    console.log('\n✅ Every spacing utility written in product code exists in the delivered CSS.');
    return;
  }
  const byToken = new Map();
  for (const d of dead) byToken.set(d.token, (byToken.get(d.token) ?? 0) + 1);
  console.error(`\n❌ ${dead.length} dead utility class(es) — written here, absent from the CSS the app loads:\n`);
  for (const [token, count] of [...byToken].sort((a, b) => b[1] - a[1])) {
    console.error(`  ${token} — ${count} use(s)`);
  }
  console.error('');
  for (const d of dead) console.error(`  ${d.file}:${d.line}  ${d.token}`);
  console.error(
    '\nThese render nothing. Either the class belongs to the design system\'s published\n' +
    'scale and the pin needs bumping, or it is outside that scale and the value has to\n' +
    'be arbitrated with design — never hardcoded back into a style attribute.',
  );
  process.exit(1);
}

main();
