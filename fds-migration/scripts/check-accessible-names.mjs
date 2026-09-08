#!/usr/bin/env node
// Fails when a design-system field this migration introduced has no accessible
// name, or carries a visible label that names nothing.
//
// WCAG 4.1.2: a control announced as "combobox" and nothing else is unusable by
// a screen reader — and unreachable by any name-based E2E locator, which is how
// this class of defect first surfaced (dashboard "Dashboard CRUD").
//
// Rules
//   1. A library <Select> (identified by <SelectTrigger>) must have a
//      <SelectLabel>, or an aria-label / aria-labelledby.
//   2. No MUI <InputLabel> may sit immediately above a library <Select>: it
//      renders as a generic, names nothing, and duplicates the real label.
//      Its text belongs in a <SelectLabel>. The MUI original expressed the same
//      association through <Select label={...}>, which does not survive conversion.
//   3. A library <Combobox> with no <ComboboxLabel> must set labelPosition="none"
//      and carry an aria-label — the library warns about exactly this case.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.argv[2] ?? 'opencti-platform/opencti-front/src';
const findings = [];

const walk = (dir) => {
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    const st = statSync(p);
    if (st.isDirectory()) { if (entry !== 'node_modules' && entry !== '__generated__') walk(p); continue; }
    if (!/\.(tsx|jsx)$/.test(entry)) continue;
    scan(p, readFileSync(p, 'utf8'));
  }
};

// The opening tag of `<Name`, returned with the block up to its closing tag.
const blocks = (src, name) => {
  const out = [];
  const re = new RegExp(`<${name}(?![A-Za-z])`, 'g');
  for (const m of src.matchAll(re)) {
    const end = src.indexOf(`</${name}>`, m.index);
    if (end === -1) continue;
    out.push({ index: m.index, line: src.slice(0, m.index).split('\n').length, body: src.slice(m.index, end) });
  }
  return out;
};

const hasAria = (s) => /aria-label(?:ledby)?=/.test(s);

// The trigger's OWN opening tag. Scanning the whole <Select> block would let the
// aria-label that rule 4 mandates on <SelectContent> satisfy rule 1, which made
// rule 1 structurally dead: removing a SelectLabel alone still reported clean.
const triggerTag = (block) => {
  const i = block.search(/<SelectTrigger(?![A-Za-z])/);
  if (i === -1) return '';
  const j = block.indexOf('>', i);
  return j === -1 ? block.slice(i) : block.slice(i, j + 1);
};

function scan(file, src) {
  if (src.includes('SelectTrigger')) {
    for (const b of blocks(src, 'Select')) {
      if (!b.body.includes('<SelectTrigger')) continue; // a MUI Select, not ours
      if (!b.body.includes('<SelectLabel') && !hasAria(triggerTag(b.body))) {
        findings.push({ file, line: b.line, rule: 'select-unnamed', msg: 'library Select has no SelectLabel and no aria-label — announced as "combobox" and nothing else' });
      }
      // The PANEL needs a name too: a page model resolves it with
      // getByRole('listbox', { name: <field> }), and an unnamed listbox is as
      // unreachable as an unnamed trigger. Caught by dashboard "Dashboard CRUD".
      if (b.body.includes('<SelectContent') && !/<SelectContent[^>]*aria-label/.test(b.body)) {
        findings.push({ file, line: b.line, rule: 'listbox-unnamed', msg: 'SelectContent has no aria-label — the panel is announced as an unnamed listbox' });
      }
      const before = src.slice(Math.max(0, b.index - 400), b.index);
      if (/<InputLabel[^>]*>[\s\S]*$/.test(before) && !/<\/Select>/.test(before.slice(before.lastIndexOf('<InputLabel')))) {
        findings.push({ file, line: b.line, rule: 'orphan-input-label', msg: 'MUI InputLabel sits above a library Select — it names nothing; move its text into a SelectLabel' });
      }
    }
  }
  if (src.includes('<Combobox')) {
    for (const b of blocks(src, 'Combobox')) {
      if (b.body.includes('<ComboboxLabel')) continue;
      if (!/labelPosition="none"/.test(b.body)) {
        findings.push({ file, line: b.line, rule: 'combobox-undeclared', msg: 'Combobox renders no ComboboxLabel but does not declare labelPosition="none"' });
      }
      if (!hasAria(b.body)) {
        findings.push({ file, line: b.line, rule: 'combobox-unnamed', msg: 'Combobox with no ComboboxLabel must carry an aria-label on ComboboxInput' });
      }
    }
  }
}

walk(ROOT);
for (const f of findings) console.log(`${f.file}:${f.line}  [${f.rule}] ${f.msg}`);
const byRule = findings.reduce((a, f) => ({ ...a, [f.rule]: (a[f.rule] ?? 0) + 1 }), {});
console.log(findings.length ? `\n${findings.length} finding(s): ${JSON.stringify(byRule)}` : 'accessible names: clean');
process.exit(findings.length ? 1 : 0);
