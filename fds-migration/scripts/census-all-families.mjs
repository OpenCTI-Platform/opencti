// Definitive census of every control family in the OpenCTI front.
//
// Method (same as census-selection-fields.mjs, generalised): resolve the LOCAL
// name of every imported symbol per file, then count `<LocalName` mounts of that
// local name. Matching on the element name is what broke two earlier counts —
// aliases and default-plus-named import forms are invisible to it.
//
// Three provenances per mount:
//   lib    — the symbol comes from '@filigran/design-system'
//   pivot  — the symbol is a product Formik adapter that is itself on the lib
//   mui    — the symbol comes from '@mui/material' or '@mui/lab'
//
// Usage: node fds-migration/scripts/census-all-families.mjs opencti-platform/opencti-front/src
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.argv[2];
const JSON_OUT = process.argv.includes('--json');

const files = [];
(function walk(d) {
  for (const e of readdirSync(d)) {
    const p = join(d, e);
    const st = statSync(p);
    if (st.isDirectory()) { if (e !== 'node_modules' && e !== '__generated__') walk(p); }
    else if (/\.(tsx|jsx)$/.test(e) && !/\.test\./.test(e)) files.push(p);
  }
})(ROOT);

// family -> { mui: [symbols], lib: [symbols], pivots: [product module paths] }
// A pivot is a product adapter ALREADY on the library: mounting it is a converted
// site, and the adapter file itself is not double-counted (its own lib mount is).
const FAMILIES = {
  Input:        { mui: ['TextField', 'Input', 'OutlinedInput', 'FilledInput', 'InputBase'], lib: ['Input'],
                  pivots: ['components/TextField', 'components/PasswordTextField', 'components/SimpleTextField', 'components/fields/BulkTextField'] },
  Textarea:     { mui: [], lib: ['Textarea'], pivots: ['components/TextareaField'] },
  Checkbox:     { mui: ['Checkbox'], lib: ['Checkbox'], pivots: ['components/CheckboxesField'] },
  Radio:        { mui: ['Radio', 'RadioGroup'], lib: ['Radio', 'RadioGroup'], pivots: [] },
  Switch:       { mui: ['Switch'], lib: ['Switch'], pivots: ['components/fields/SwitchField'] },
  Select:       { mui: ['Select', 'NativeSelect'], lib: ['Select'], pivots: ['components/fields/SelectFieldFds'] },
  Combobox:     { mui: ['Autocomplete'], lib: ['Combobox'], pivots: ['components/ComboboxField', 'components/fields/EntitySelectWithTypes'] },
  SearchField:  { mui: [], lib: ['SearchField'], pivots: [] },
  Button:       { mui: ['Button', 'LoadingButton'], lib: ['Button'], pivots: [] },
  IconButton:   { mui: ['IconButton'], lib: ['IconButton'], pivots: [] },
  Chip:         { mui: ['Chip'], lib: ['Chip'], pivots: [] },
  Fab:          { mui: ['Fab'], lib: [], pivots: [] },
  ToggleButton: { mui: ['ToggleButton', 'ToggleButtonGroup'], lib: ['ButtonGroup'], pivots: ['components/fields/ToggleButtonField'] },
  Slider:       { mui: ['Slider'], lib: ['Slider'], pivots: ['components/InputSliderField', 'components/fields/SliderField'] },
};

const MUI_TO_FAMILY = new Map();
const LIB_TO_FAMILY = new Map();
for (const [fam, def] of Object.entries(FAMILIES)) {
  for (const s of def.mui) MUI_TO_FAMILY.set(s, fam);
  for (const s of def.lib) LIB_TO_FAMILY.set(s, fam);
}
// pivot module suffix -> family
const PIVOT_TO_FAMILY = new Map();
for (const [fam, def] of Object.entries(FAMILIES)) for (const p of def.pivots) PIVOT_TO_FAMILY.set(p, fam);

const MUI_PKG = /^@mui\/(material|lab)(\/([A-Za-z]+))?$/;

// Type-only symbols imported without the `type` keyword. `<SelectProps` matches
// the element regex inside `Omit<SelectProps<string>, …>`, so these produced
// mount counts for things that are never mounted. Verified by reading the
// matches: every one sits in a generic position.
const TYPE_ONLY = /(?:Props|TypeMap)$/;

// Every MUI symbol that is NOT one of the 14 control families gets a bucket
// here, so the "uncensused" bucket can be PROVEN empty rather than asserted.
// A bucket is a statement about scope, not about readiness — `lib-exists` means
// the library ships a replacement and the family is simply not this wave's
// scope; `no-lib-equivalent` means there is nothing to convert onto today.
const BUCKETS = {
  'lib-exists — not this wave': [
    'Typography', 'Tooltip', 'Menu', 'MenuItem', 'MenuList', 'Dialog', 'DialogActions',
    'DialogContent', 'DialogContentText', 'DialogTitle', 'Tab', 'Tabs', 'Badge', 'Paper',
    'Card', 'CardContent', 'CardHeader', 'CardActions', 'CardActionArea', 'CircularProgress',
    'LinearProgress', 'AppBar', 'Toolbar', 'ButtonGroup', 'Icon',
  ],
  'no-lib-equivalent — container / layout': [
    'Grid', 'Grid2', 'Box', 'Stack', 'Divider', 'Drawer', 'Accordion', 'AccordionSummary',
    'AccordionDetails', 'Collapse', 'Modal', 'Popover', 'Popper', 'Grow', 'Slide',
    'ClickAwayListener', 'CssBaseline', 'ButtonBase',
  ],
  'no-lib-equivalent — list / table / data display': [
    'List', 'ListItem', 'ListItemText', 'ListItemIcon', 'ListItemButton', 'ListItemAvatar',
    'ListItemSecondaryAction', 'ListSubheader', 'Table', 'TableBody', 'TableCell', 'TableHead',
    'TableRow', 'TableContainer', 'Avatar', 'Skeleton', 'ImageListItem', 'ImageListItemBar',
    'Timeline', 'TimelineItem', 'TimelineDot', 'TimelineConnector', 'TimelineContent',
    'TimelineSeparator', 'TimelineOppositeContent', 'Step', 'Stepper', 'StepButton', 'StepLabel',
  ],
  'no-lib-equivalent — feedback': ['Alert', 'AlertTitle', 'Snackbar'],
  'no-lib-equivalent — speed dial': ['SpeedDial', 'SpeedDialIcon', 'SpeedDialAction'],
  'form scaffolding — follows its control, never converted alone': [
    'FormControl', 'FormControlLabel', 'FormGroup', 'FormHelperText', 'FormLabel',
    'InputLabel', 'InputAdornment',
  ],
};
const SYMBOL_BUCKET = new Map();
for (const [b, syms] of Object.entries(BUCKETS)) for (const s of syms) SYMBOL_BUCKET.set(s, b);

// Every MUI symbol seen anywhere, so the "uncensused" bucket can be proven empty.
const allMuiSymbols = new Map(); // symbol -> mounts

const sites = [];   // one row per mount
const pivotFiles = new Set();

for (const f of files) {
  const raw = readFileSync(f, 'utf8');
  // strip comments so a commented-out element never counts
  const src = raw.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
  const rel = f.slice(f.indexOf('opencti-front/') + 'opencti-front/'.length);

  const local = new Map(); // localName -> { origin, symbol }

  // default / namespace imports:  import X from '<mod>'   (optionally + named)
  for (const m of src.matchAll(/import\s+([A-Za-z_$][\w$]*)\s*(?:,\s*\{([^}]*)\})?\s*from\s*['"]([^'"]+)['"]/g)) {
    const [, def, named, mod] = m;
    const mui = MUI_PKG.exec(mod);
    if (mui && mui[3]) local.set(def, { origin: 'mui', symbol: mui[3] });
    for (const [suffix, fam] of PIVOT_TO_FAMILY) {
      if (mod.endsWith(suffix) || mod.endsWith(suffix.replace(/^components\//, ''))) {
        local.set(def, { origin: 'pivot', symbol: fam }); break;
      }
    }
    if (named) addNamed(named, mod, local);
  }
  // pure named imports:  import { A, B as C } from '<mod>'
  // `import type { … }` is skipped wholesale: a type name only ever appears in a
  // generic position (`Omit<SelectProps, …>`), and `<SelectProps` matches the
  // element regex there. That is what put SelectProps/PopoverProps/GridTypeMap
  // in the first inventory with mount counts they cannot have.
  for (const m of src.matchAll(/import\s+(type\s+)?\{([^}]*)\}\s*from\s*['"]([^'"]+)['"]/gs)) {
    if (m[1]) continue;
    addNamed(m[2], m[3], local);
  }

  function addNamed(list, mod, map) {
    const isMui = MUI_PKG.test(mod) && !RegExp.$3;
    const isLib = mod === '@filigran/design-system';
    if (!isMui && !isLib) return;
    for (const part of list.split(',')) {
      const t = part.trim();
      if (!t || /^type\s/.test(t)) continue;
      const as = t.match(/^([A-Za-z_$][\w$]*)\s+as\s+([A-Za-z_$][\w$]*)$/);
      const name = as ? as[1] : t;
      const localName = as ? as[2] : t;
      if (isMui && TYPE_ONLY.test(name)) continue;
      if (isMui) map.set(localName, { origin: 'mui', symbol: name });
      else map.set(localName, { origin: 'lib', symbol: name });
    }
  }

  for (const [localName, { origin, symbol }] of local) {
    // Two mount forms in this codebase: the JSX element, and Formik's
    // `component={X}`. Counting only the first is what hid 108 SwitchField and
    // 102 SelectFieldFds sites from the first pass of this script.
    const re = new RegExp(`<${localName}(?![A-Za-z0-9_$])|component=\\{${localName}\\}`, 'g');
    for (const m of src.matchAll(re)) {
      const line = src.slice(0, m.index).split('\n').length;
      if (origin === 'mui') {
        allMuiSymbols.set(symbol, (allMuiSymbols.get(symbol) ?? 0) + 1);
        const fam = MUI_TO_FAMILY.get(symbol);
        if (!fam) continue;
        // multiline TextField is the Textarea family, not Input
        let family = fam;
        if (symbol === 'TextField') {
          const close = src.indexOf('/>', m.index);
          const tag = src.slice(m.index, close === -1 ? m.index + 1200 : close);
          if (/\bmultiline\b/.test(tag)) family = 'Textarea';
        }
        sites.push({ rel, line, family, provenance: 'mui', symbol, localName });
      } else if (origin === 'lib') {
        const fam = LIB_TO_FAMILY.get(symbol);
        if (!fam) continue;
        sites.push({ rel, line, family: fam, provenance: 'lib', symbol, localName });
      } else {
        pivotFiles.add(rel);
        sites.push({ rel, line, family: symbol, provenance: 'pivot', symbol: localName, localName });
      }
    }
  }
}

// ── Roll-up ────────────────────────────────────────────────────────────────
const byFamily = {};
for (const fam of Object.keys(FAMILIES)) byFamily[fam] = { lib: 0, pivot: 0, mui: 0, muiSites: [] };
for (const s of sites) {
  const b = byFamily[s.family];
  b[s.provenance] += 1;
  if (s.provenance === 'mui') b.muiSites.push(s);
}

if (JSON_OUT) {
  console.log(JSON.stringify({ byFamily, allMuiSymbols: Object.fromEntries([...allMuiSymbols].sort((a, b) => b[1] - a[1])) }, null, 2));
} else {
  let tl = 0, tp = 0, tm = 0;
  console.log('| family | total | on lib | on MUI |');
  console.log('|---|---:|---:|---:|');
  for (const [fam, b] of Object.entries(byFamily)) {
    const total = b.lib + b.pivot + b.mui;
    tl += b.lib; tp += b.pivot; tm += b.mui;
    console.log(`| ${fam} | ${total} | ${b.lib + b.pivot} (${b.lib} direct + ${b.pivot} pivot) | ${b.mui} |`);
  }
  console.log(`| **TOTAL** | **${tl + tp + tm}** | **${tl + tp}** | **${tm}** |`);
  console.log('\n## MUI sites, by family\n');
  for (const [fam, b] of Object.entries(byFamily)) {
    if (!b.mui) continue;
    console.log(`### ${fam} — ${b.mui}`);
    for (const s of b.muiSites) console.log(`- ${s.rel}:${s.line}  <${s.localName}> (${s.symbol})`);
    console.log('');
  }
  console.log('## Every MUI symbol mounted anywhere\n');
  const uncensused = [];
  const buckets = new Map();
  for (const [sym, n] of [...allMuiSymbols].sort((a, b) => b[1] - a[1])) {
    if (MUI_TO_FAMILY.has(sym)) continue;
    const b = SYMBOL_BUCKET.get(sym);
    if (!b) { uncensused.push([sym, n]); continue; }
    if (!buckets.has(b)) buckets.set(b, []);
    buckets.get(b).push([sym, n]);
  }
  const famTotal = [...allMuiSymbols].filter(([s]) => MUI_TO_FAMILY.has(s)).reduce((a, [, n]) => a + n, 0);
  console.log(`Distinct MUI symbols mounted: ${allMuiSymbols.size}`);
  console.log(`- in a censused control family: ${[...allMuiSymbols.keys()].filter((s) => MUI_TO_FAMILY.has(s)).length} symbols / ${famTotal} mounts`);
  for (const [b, list] of buckets) {
    const n = list.reduce((a, [, c]) => a + c, 0);
    console.log(`- ${b}: ${list.length} symbols / ${n} mounts`);
    console.log(`  ${list.map(([s, c]) => `${s} (${c})`).join(', ')}`);
  }
  console.log(`\n**Uncensused: ${uncensused.length}**` + (uncensused.length ? ` — ${uncensused.map(([s, n]) => `${s} (${n})`).join(', ')}` : ' ✅'));
  if (uncensused.length) process.exitCode = 1;
}
