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
