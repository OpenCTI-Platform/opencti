// Pure helpers for sync.mjs: post-processing of the generated oxlint config.

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
