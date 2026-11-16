import path from 'node:path';

/** @typedef {{ file: string, line: number, ruleId: string, severity: 'error'|'warning' }} Finding */
/** @typedef {{ rule: string, files?: string, reason: string }} AllowEntry */
/** @typedef {{ rule: string, reason: string }} EslintOnlyEntry */

// oxlint plugin name (config key prefix or diagnostic code scope) -> ESLint rule id prefix.
// An empty prefix means core ESLint rules, which carry no prefix.
// An unknown plugin is kept as-is on purpose: it surfaces as a difference.
const PLUGIN_PREFIXES = {
  eslint: '',
  typescript: '@typescript-eslint',
  'typescript-eslint': '@typescript-eslint',
  '@typescript-eslint': '@typescript-eslint',
  react: 'react',
  'react-hooks': 'react-hooks',
  react_hooks: 'react-hooks',
  import: 'import',
  'jsx-a11y': 'jsx-a11y',
  jsx_a11y: 'jsx-a11y',
  unicorn: 'unicorn',
  promise: 'promise',
  node: 'n',
  n: 'n',
};

const joinRuleId = (plugin, rule) => {
  const key = plugin.replace(/^eslint-plugin-/, '');
  const prefix = Object.hasOwn(PLUGIN_PREFIXES, key) ? PLUGIN_PREFIXES[key] : key;
  return prefix ? `${prefix}/${rule}` : rule;
};

/**
 * Maps an oxlint config key (`typescript/no-unused-vars`) or diagnostic code
 * (`typescript-eslint(no-unused-vars)`) to the ESLint rule id.
 * @param {string} id
 * @returns {string}
 */
export const toEslintRuleId = (id) => {
  const code = /^(.+)\((.+)\)$/.exec(id);
  if (code) return joinRuleId(code[1], code[2]);
  const slash = id.lastIndexOf('/');
  if (slash === -1) return id;
  return joinRuleId(id.slice(0, slash), id.slice(slash + 1));
};

const toPosix = (p) => p.split(path.sep).join('/');

// ESLint reports absolute paths, oxlint reports paths relative to its cwd:
// both become package-relative POSIX paths, relative to baseDir.
const toRelativeFile = (file, baseDir) => toPosix(path.relative(baseDir, path.resolve(baseDir, file)));

const ESLINT_SEVERITIES = { 2: 'error', 1: 'warning' };

/**
 * @param {object[]} results ESLint `--format json` output
 * @param {string} baseDir
 * @returns {Finding[]}
 */
export const normalizeEslint = (results, baseDir) => results.flatMap((result) => {
  const file = toRelativeFile(result.filePath, baseDir);
  return result.messages
    .filter((message) => message.ruleId)
    .map((message) => ({
      file,
      line: message.line,
      ruleId: message.ruleId,
      severity: ESLINT_SEVERITIES[message.severity] ?? 'error',
    }));
});

/**
 * @param {{ diagnostics: object[] }} report oxlint `--format json` output
 * @param {string} baseDir
 * @returns {Finding[]}
 */
export const normalizeOxlint = (report, baseDir) => report.diagnostics
  .filter((diagnostic) => diagnostic.code)
  .map((diagnostic) => ({
    file: toRelativeFile(diagnostic.filename, baseDir),
    line: diagnostic.labels?.[0]?.span?.line ?? 0,
    ruleId: toEslintRuleId(diagnostic.code),
    severity: diagnostic.severity === 'warning' ? 'warning' : 'error',
  }));

const isEnabled = (setting) => {
  const level = Array.isArray(setting) ? setting[0] : setting;
  return level !== 'off' && level !== 'allow' && level !== 0;
};

/**
 * ESLint ids of the rules that are not `off` in the top-level `rules` or in any `overrides[].rules`.
 * @param {{ rules?: object, overrides?: { rules?: object }[] }} oxlintrc
 * @returns {Set<string>}
 */
export const oxlintConfigRules = (oxlintrc) => {
  const rulesets = [oxlintrc.rules ?? {}, ...(oxlintrc.overrides ?? []).map((override) => override.rules ?? {})];
  const enabled = new Set();
  for (const rules of rulesets) {
    for (const [key, setting] of Object.entries(rules)) {
      if (isEnabled(setting)) enabled.add(toEslintRuleId(key));
    }
  }
  return enabled;
};
