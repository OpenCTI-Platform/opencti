#!/usr/bin/env node
/**
 * MenuItem / Menu guard for the MUI-Select -> library-Select conversion.
 *
 * HAND-WRITTEN and product-specific — unlike check-fds-conformity.mjs in this
 * directory, this is NOT a generated template. Edit it here.
 *
 * Why it exists: converting a MUI Select means renaming its `<MenuItem>`
 * children to `<SelectItem>`, and `MenuItem` also builds real action menus. A
 * blanket rename therefore silently eats a menu's items. The manual guard for
 * this missed a case — it matched `<Menu` followed by a space or `>` but not by
 * a NEWLINE, so a file with a six-item action menu reported zero menus. This
 * replaces that vigilance with a gate, because a gate survives a session.
 *
 * Three things it had to learn to avoid crying wolf, each found by running it:
 *   - `MenuItem` appears in COMMENTS (this repo's own adapter documents it), so
 *     comments are stripped before analysis;
 *   - imports are often MULTI-LINE combined `{ ... } from '@mui/material'`, so
 *     import detection spans statements rather than lines;
 *   - the DESIGN SYSTEM ships its own `Menu`/`MenuItem` too, so an import from
 *     '@filigran/design-system' counts just as much as one from MUI.
 * A gate that reports false positives gets ignored, which defeats its purpose.
 *
 * Zero dependencies, plain Node, .mjs so it is ESM regardless of the product's
 * package.json "type".
 *
 *   node fds-migration/scripts/check-select-conversion.mjs
 *
 * Exit 0 and NO output when clean. Any finding is printed and exits 1.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = 'opencti-platform/opencti-front/src';

const walk = (dir, out = []) => {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      if (entry !== '__generated__' && entry !== 'node_modules') walk(full, out);
    } else if (/\.(tsx|jsx)$/.test(entry)) out.push(full);
  }
  return out;
};

/** Blank out block and line comments, keeping newlines so lines still align. */
const stripComments = (src) => src
  .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
  .replace(/^[ \t]*\/\/.*$/gm, '');

/** Does any import statement bring in `name` from one of the given packages? */
const importsFrom = (src, name, packages) => {
  const re = /import\s+([\s\S]*?)\s+from\s+['"]([^'"]+)['"]/g;
  for (const [, clause, pkg] of src.matchAll(re)) {
    if (!packages.some((p) => pkg === p || pkg.startsWith(`${p}/`) || pkg.endsWith(p))) continue;
    if (new RegExp(`\\b${name}\\b`).test(clause)) return true;
  }
  return false;
};

// `<Menu` followed by ANY whitespace or `>` — the newline case is the one the
// manual guard missed.
const REAL_MENU = /<Menu[\s>]/;
const MENU_PKGS = ['@mui/material', '@mui/material/MenuItem', '@filigran/design-system'];
const ITEM_PKGS = ['@filigran/design-system', 'SelectFieldFds'];
const findings = [];

for (const file of walk(ROOT)) {
  const raw = readFileSync(file, 'utf8');
  const src = stripComments(raw);
  const rel = file.replace(`${ROOT}/`, '');

  const usesMenuItem = src.includes('<MenuItem');
  const usesSelectItem = src.includes('<SelectItem');
  const hasRealMenu = REAL_MENU.test(src);

  if (usesMenuItem && !importsFrom(src, 'MenuItem', MENU_PKGS)) {
    findings.push(`${rel}: uses <MenuItem> with no MenuItem import — a rename removed an import that is still needed`);
  }
  if (usesSelectItem && !importsFrom(src, 'SelectItem', ITEM_PKGS)) {
    findings.push(`${rel}: uses <SelectItem> with no SelectItem import`);
  }
  if (hasRealMenu && usesSelectItem && !usesMenuItem) {
    findings.push(`${rel}: has a real <Menu> and <SelectItem> but no <MenuItem> left — the menu's own items were probably renamed`);
  }
}

if (findings.length) {
  console.error(`check-select-conversion: ${findings.length} finding(s)\n`);
  for (const f of findings) console.error(`  ${f}`);
  process.exit(1);
}
