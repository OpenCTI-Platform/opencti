#!/usr/bin/env node
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { oxlintConfigRules, toComparableRuleId, toEslintRuleId } from './normalize.mjs';
import { anchorOverrideGlobs, compareConfigs, excludeBlockIgnores, serializeConfig } from './oxlintrc.mjs';

// Regenerates .oxlintrc.json from eslint.config.ts (run from a package dir) so that
// oxlint runs exactly the rules ESLint enables, then reports what could not be carried over.
// With --check nothing is written: the generated config is compared to the committed one
// (exit 0 identical, 1 drift, 2 error).
const CHECK = process.argv.includes('--check');

const ESLINT_CONFIG = 'eslint.config.ts';
const OXLINTRC = '.oxlintrc.json';
// Every oxlint category: none may run by default, only the rules ESLint enables.
const CATEGORIES = ['correctness', 'suspicious', 'pedantic', 'perf', 'style', 'restriction', 'nursery'];

const packageDir = process.cwd();

const fail = (message) => {
  console.error(`lint-parity sync: ${message}`);
  process.exit(2);
};

// The package declares the bin as "@oxlint/migrate", which yarn does not link into node_modules/.bin:
// the entry point is read from the package manifest instead.
const migrateEntryPoint = () => {
  const manifestFile = path.join(packageDir, 'node_modules', '@oxlint', 'migrate', 'package.json');
  if (!fs.existsSync(manifestFile)) fail(`@oxlint/migrate is not installed (${manifestFile} not found)`);
  const { bin } = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));
  const entry = typeof bin === 'string' ? bin : Object.values(bin ?? {})[0];
  if (!entry) fail('@oxlint/migrate declares no bin');
  return path.resolve(path.dirname(manifestFile), entry);
};

// Runs the migration into a scratch directory, so no file of the package is ever touched, and returns the raw config.
const runMigrate = () => {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'lint-parity-sync-'));
  try {
    const output = path.join(scratch, OXLINTRC);
    // migrate resolves --output-file against its working directory even when it is absolute: pass it relative.
    const run = spawnSync(
      process.execPath,
      // --js-plugins=false: no `jsPlugins`, rules oxlint lacks stay ESLint-only. No --type-aware.
      [migrateEntryPoint(), ESLINT_CONFIG, '--js-plugins=false', '--output-file', path.relative(packageDir, output)],
      { cwd: packageDir, encoding: 'utf8' },
    );
    if (run.error || run.status !== 0) {
      fail(`oxlint-migrate failed (exit ${run.status}): ${run.error?.message ?? (run.stderr || run.stdout).trim()}`);
    }
    return JSON.parse(fs.readFileSync(output, 'utf8'));
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
};

const loadEslintConfig = async () => {
  const module = await import(pathToFileURL(path.join(packageDir, ESLINT_CONFIG)).href);
  return module.default;
};

// A global ignore is a config object whose only keys are `ignores` and optionally `name`.
// The .gitignore files are not copied: oxlint reads them itself.
const globalIgnores = (eslintConfig) => eslintConfig
  .filter((entry) => Object.keys(entry).every((key) => key === 'ignores' || key === 'name'))
  .flatMap((entry) => entry.ignores ?? []);

const settingLevel = (setting) => (Array.isArray(setting) ? setting[0] : setting);
const settingOptions = (setting) => (Array.isArray(setting) ? setting.slice(1) : []);
const isEnabled = (setting) => !['off', 'allow', 0].includes(settingLevel(setting));

// Stable text for a set of options, whatever the key order.
const canonical = (value) => JSON.stringify(value, (_key, nested) => (
  nested && typeof nested === 'object' && !Array.isArray(nested)
    ? Object.fromEntries(Object.entries(nested).sort(([a], [b]) => a.localeCompare(b)))
    : nested
));

// rule id -> set of distinct option lists it is enabled with, across the given rule sets.
const enabledOptions = (rulesets, toRuleId) => {
  const byRule = new Map();
  for (const rules of rulesets) {
    for (const [key, setting] of Object.entries(rules)) {
      if (!isEnabled(setting)) continue;
      const id = toRuleId(key);
      if (!byRule.has(id)) byRule.set(id, new Set());
      byRule.get(id).add(canonical(settingOptions(setting)));
    }
  }
  return byRule;
};

// oxlint validates the options of a rule even when it is off, and rejects options it does not know
// (ESLint presets carry such options for rules they turn off). An off rule needs no options.
const stripOffRuleOptions = (rules) => {
  for (const [key, setting] of Object.entries(rules ?? {})) {
    if (Array.isArray(setting) && !isEnabled(setting)) rules[key] = settingLevel(setting);
  }
};

const printList = (title, items) => {
  console.log(`${title} (${items.length})`);
  items.forEach((item) => console.log(`  ${item}`));
};

const main = async () => {
  if (!fs.existsSync(path.join(packageDir, ESLINT_CONFIG))) fail(`${ESLINT_CONFIG} not found in ${packageDir}`);
  const eslintConfig = await loadEslintConfig();

  const migrated = runMigrate();
  migrated.categories = Object.fromEntries(CATEGORIES.map((category) => [category, 'off']));
  stripOffRuleOptions(migrated.rules);
  (migrated.overrides ?? []).forEach((override) => stripOffRuleOptions(override.rules));
  migrated.ignorePatterns = [...new Set(globalIgnores(eslintConfig))];
  let excludeResult;
  try {
    excludeResult = excludeBlockIgnores(migrated, eslintConfig);
  } catch (error) {
    fail(error.message);
  }
  const { config: oxlintrc, rewritten } = anchorOverrideGlobs(excludeResult.config);
  const generated = serializeConfig(oxlintrc);
  const file = path.join(packageDir, OXLINTRC);

  if (CHECK) {
    const { match, reason } = compareConfigs(generated, fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : undefined);
    if (match) {
      console.log(`${OXLINTRC} is up to date with ${ESLINT_CONFIG}`);
      return;
    }
    console.log(`${OXLINTRC} is out of date with ${ESLINT_CONFIG}: ${reason}. Run \`yarn lint:ox:sync\` and commit the result.`);
    process.exit(1);
  }
  fs.writeFileSync(file, generated);

  // Both sides are keyed by the id oxlint enforces: ESLint's @typescript-eslint/x folded into the core x where migrate does.
  const eslintOptions = enabledOptions(eslintConfig.map((entry) => entry.rules ?? {}), toComparableRuleId);
  const oxlintOptions = enabledOptions(
    [oxlintrc.rules ?? {}, ...(oxlintrc.overrides ?? []).map((override) => override.rules ?? {})],
    (key) => toComparableRuleId(toEslintRuleId(key)),
  );
  const oxlintRules = oxlintConfigRules(oxlintrc);

  const unsupported = [...eslintOptions.keys()].filter((id) => !oxlintRules.has(id)).sort();
  const optionsDiffer = [...eslintOptions.keys()]
    .filter((id) => oxlintOptions.has(id))
    .filter((id) => [...eslintOptions.get(id)].sort().join('\n') !== [...oxlintOptions.get(id)].sort().join('\n'))
    .sort();

  console.log(`${OXLINTRC} written: ${oxlintRules.size} rules enabled, ${oxlintrc.ignorePatterns.length} ignore patterns`);
  printList('override globs anchored to the package root (ESLint flat config semantics)', rewritten.map((item) => `override ${item.override}: ${item.before} -> ${item.after}`));
  printList('block ignores turned into an override that sets the block\'s rules off', excludeResult.excluded.map((item) => `after override ${item.override}: ${item.files.join(', ')}`));
  printList('ESLint-only, unsupported by oxlint', unsupported);
  printList('options differ, check in triage', optionsDiffer);
};

main().catch((error) => fail(error.stack));
