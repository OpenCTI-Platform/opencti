// Pure helpers for sync.mjs: post-processing of the generated oxlint config and the drift comparison.

// In ESLint flat config a `files` pattern without a slash (`*.js`, `knip.ts`) is matched against the path
// relative to the config directory, so it only matches files at the package root. oxlint matches the same
// pattern against the basename, at any depth. oxlint 1.93.0 has a form that is root-only: a `./` prefix
// (`./*.js` matches `root.js`, not `src/a.js`). `/*.js` matches nothing, and `./` is relative to the config
// directory whatever the working directory is.
const hasSlash = (pattern) => pattern.includes('/');
const isNegated = (pattern) => pattern.startsWith('!');

export const rootAnchorGlob = (pattern) => (hasSlash(pattern) || isNegated(pattern) ? pattern : `./${pattern}`);

// Returns a copy of the config where every slash-less override pattern is root-anchored, and the list of
// `{ override, before, after }` that were rewritten (override is the index in `overrides`).
export const anchorOverrideGlobs = (oxlintrc) => {
  const rewritten = [];
  const overrides = (oxlintrc.overrides ?? []).map((override, index) => {
    if (!Array.isArray(override.files)) return override;
    const files = override.files.map((pattern) => {
      const after = rootAnchorGlob(pattern);
      if (after !== pattern) rewritten.push({ override: index, before: pattern, after });
      return after;
    });
    return { ...override, files };
  });
  return { config: oxlintrc.overrides ? { ...oxlintrc, overrides } : oxlintrc, rewritten };
};

const isEnabledSetting = (setting) => !['off', 'allow', 0].includes(Array.isArray(setting) ? setting[0] : setting);
const sameList = (a, b) => a.length === b.length && a.every((item, index) => item === b[index]);

// An ESLint block with both `files` and `ignores` skips its ignored files. @oxlint/migrate drops those
// `ignores`, and oxlint 1.93.0 overrides have no exclusion (a `!` pattern in `files` is just another match).
// So right after the block's migrated override, a second override turns the block's rules off for its
// ignored files. That is exact only when no earlier block enables the same rule (the ignored files would
// keep that earlier setting in ESLint, `off` would hide it), so that case fails instead of guessing.
// Returns a copy of the config and the list of `{ override, files }` that were excluded (override is the
// index of the block's override in the input `overrides`).
export const excludeBlockIgnores = (oxlintrc, eslintConfig) => {
  const overrides = [...(oxlintrc.overrides ?? [])];
  const excluded = [];
  eslintConfig.forEach((entry, index) => {
    if (!Array.isArray(entry.files) || !Array.isArray(entry.ignores) || !entry.rules) return;
    const matches = overrides
      .map((override, position) => ({ override, position }))
      .filter(({ override }) => Array.isArray(override.files) && sameList(override.files, entry.files)
        && Object.keys(override.rules ?? {}).length === Object.keys(entry.rules).length);
    if (matches.length !== 1) {
      throw new Error(`block with files ${JSON.stringify(entry.files)} has ignores, and ${matches.length} migrated overrides match it (expected 1)`);
    }
    for (const [rule, setting] of Object.entries(entry.rules)) {
      if (!isEnabledSetting(setting)) continue;
      if (eslintConfig.slice(0, index).some((earlier) => isEnabledSetting(earlier.rules?.[rule] ?? 'off'))) {
        throw new Error(`${rule} is enabled by an earlier block and by a block with ignores ${JSON.stringify(entry.ignores)}: turning it off for those files would hide the earlier setting`);
      }
    }
    const { override, position } = matches[0];
    const rules = Object.fromEntries(Object.keys(override.rules).map((rule) => [rule, 'off']));
    overrides.splice(position + 1, 0, { files: [...entry.ignores], rules });
    excluded.push({ override: (oxlintrc.overrides ?? []).indexOf(override), files: [...entry.ignores] });
  });
  return { config: excluded.length ? { ...oxlintrc, overrides } : oxlintrc, excluded };
};

export const serializeConfig = (oxlintrc) => `${JSON.stringify(oxlintrc, null, 2)}\n`;

const summarize = (lines, other) => {
  const index = lines.findIndex((line, i) => line !== other[i]);
  return index === -1 ? lines.length : index;
};

// Compares the generated config text with the committed one. `committed` is undefined when the file is missing.
export const compareConfigs = (generated, committed) => {
  if (committed === undefined) return { match: false, reason: 'the committed file does not exist' };
  if (generated === committed) return { match: true, reason: '' };
  const generatedLines = generated.split('\n');
  const committedLines = committed.split('\n');
  const first = summarize(generatedLines, committedLines);
  return {
    match: false,
    reason: `first difference at line ${first + 1} (generated ${generatedLines.length} lines, committed ${committedLines.length})`,
  };
};
