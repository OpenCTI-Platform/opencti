// Census of selection fields. Resolves the LOCAL name of each imported symbol
// per file, so an alias (`import MUIAutocomplete from '@mui/material/Autocomplete'`)
// is counted. Matching on the element name is what missed both earlier counts.
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.argv[2];
const files = [];
(function walk(d) {
  for (const e of readdirSync(d)) {
    const p = join(d, e);
    const st = statSync(p);
    if (st.isDirectory()) { if (e !== 'node_modules' && e !== '__generated__') walk(p); }
    else if (/\.(tsx|jsx)$/.test(e) && !/\.test\./.test(e)) files.push(p);
  }
})(ROOT);

// Which imported symbols count as a MUI selection field.
const MUI_SELECTION = {
  '@mui/material/Select': 'default',
  '@mui/material/Autocomplete': 'default',
  '@mui/material/NativeSelect': 'default',
};
const MUI_NAMED = new Set(['Select', 'Autocomplete', 'NativeSelect']);
// Product pivots and library entry points that mean CONVERTED.
const CONVERTED_MARKERS = [
  ['component={SelectFieldFds}', 'Select pivot'],
  ['component={ComboboxField}', 'Combobox pivot'],
];

const rows = [];
for (const f of files) {
  const src = readFileSync(f, 'utf8');
  const rel = f.replace(`${ROOT}/`, '');
  const local = new Map(); // localName -> kind

  // default imports: import X from '@mui/material/Select'
  for (const m of src.matchAll(/import\s+([A-Za-z_$][\w$]*)\s*(?:,\s*\{[^}]*\})?\s*from\s*['"]([^'"]+)['"]/g)) {
    const kind = MUI_SELECTION[m[2]];
    if (kind) local.set(m[1], m[2].split('/').pop());
  }
  // named imports: import { Select as X, Autocomplete } from '@mui/material'
  for (const m of src.matchAll(/import\s*(?:type\s*)?\{([^}]*)\}\s*from\s*['"]@mui\/material['"]/gs)) {
    for (const part of m[1].split(',')) {
      const t = part.trim();
      if (!t) continue;
      const as = t.match(/^([A-Za-z_$][\w$]*)\s+as\s+([A-Za-z_$][\w$]*)$/);
      const name = as ? as[1] : t;
      const localName = as ? as[2] : t;
      if (MUI_NAMED.has(name)) local.set(localName, name);
    }
  }

  const muiMounts = [];
  for (const [name, kind] of local) {
    const re = new RegExp(`<${name}(?![A-Za-z0-9_$])`, 'g');
    for (const m of src.matchAll(re)) {
      // a library Select block contains SelectTrigger; skip those
      if (kind === 'Select') {
        const end = src.indexOf('</', m.index);
        const close = src.indexOf(`</${name}>`, m.index);
        const block = close === -1 ? src.slice(m.index, m.index + 2000) : src.slice(m.index, close);
        if (/<SelectTrigger\b/.test(block)) continue;
      }
      muiMounts.push({ name, kind, line: src.slice(0, m.index).split('\n').length });
    }
  }
  const converted = CONVERTED_MARKERS
    .map(([needle, label]) => [label, src.split(needle).length - 1])
    .filter(([, n]) => n > 0);
  const libDirect = (src.match(/<Combobox(?![A-Za-z])/g) || []).length
    + [...src.matchAll(/<Select(?![A-Za-z])/g)].filter((m) => {
      const close = src.indexOf('</Select>', m.index);
      return close !== -1 && /<SelectTrigger\b/.test(src.slice(m.index, close));
    }).length;

  if (muiMounts.length || converted.length || libDirect) {
    rows.push({ rel, muiMounts, converted, libDirect });
  }
}

const totalMui = rows.reduce((a, r) => a + r.muiMounts.length, 0);
const totalPivots = rows.reduce((a, r) => a + r.converted.reduce((x, [, n]) => x + n, 0), 0);
const totalDirect = rows.reduce((a, r) => a + r.libDirect, 0);
console.log(`CONVERTED  pivot mounts: ${totalPivots}   direct library mounts: ${totalDirect}   (total ${totalPivots + totalDirect})`);
console.log(`REMAINING  MUI selection mounts: ${totalMui}\n`);
console.log('Files with MUI selection mounts left:');
for (const r of rows.filter((x) => x.muiMounts.length).sort((a, b) => b.muiMounts.length - a.muiMounts.length)) {
  const by = {};
  for (const m of r.muiMounts) by[`${m.name}:${m.kind}`] = (by[`${m.name}:${m.kind}`] || 0) + 1;
  console.log(`  ${String(r.muiMounts.length).padStart(2)}  ${r.rel}   [${Object.entries(by).map(([k, v]) => `${k}x${v}`).join(' ')}]`);
}
