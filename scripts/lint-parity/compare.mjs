import path from 'node:path';

/** @typedef {import('./normalize.mjs').Finding} Finding */
/** @typedef {import('./normalize.mjs').AllowEntry} AllowEntry */
/** @typedef {import('./normalize.mjs').EslintOnlyEntry} EslintOnlyEntry */
/**
 * @typedef {{
 *   onlyEslint: Finding[],
 *   onlyOxlint: Finding[],
 *   severityMismatch: { eslint: Finding, oxlint: Finding }[],
 *   eslintOnlySkipped: Record<string, number>,
 *   staleAllowlist: AllowEntry[],
 * }} CompareResult
 */

const keyOf = (finding) => `${finding.file}|${finding.line}|${finding.ruleId}`;

const groupByKey = (findings) => {
  const groups = new Map();
  for (const finding of findings) {
    const key = keyOf(finding);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(finding);
  }
  return groups;
};

const allowMatches = (entry, finding) => entry.rule === finding.ruleId
  && (entry.files === undefined || path.matchesGlob(finding.file, entry.files));

/**
 * Compares ESLint and oxlint findings as multisets keyed by file, line and rule.
 * @param {{ eslint: Finding[], oxlint: Finding[], oxlintRules: Set<string>, eslintOnly: EslintOnlyEntry[], allowlist: AllowEntry[] }} input
 * @returns {CompareResult}
 */
export const compareFindings = ({ eslint, oxlint, oxlintRules, eslintOnly, allowlist }) => {
  const eslintOnlyRules = new Set(eslintOnly.map((entry) => entry.rule));
  const eslintOnlySkipped = {};
  const comparableEslint = eslint.filter((finding) => {
    if (!eslintOnlyRules.has(finding.ruleId) && oxlintRules.has(finding.ruleId)) return true;
    eslintOnlySkipped[finding.ruleId] = (eslintOnlySkipped[finding.ruleId] ?? 0) + 1;
    return false;
  });
  const eslintGroups = groupByKey(comparableEslint);
  const oxlintGroups = groupByKey(oxlint);

  const onlyEslint = [];
  const onlyOxlint = [];
  const severityMismatch = [];
  for (const key of new Set([...eslintGroups.keys(), ...oxlintGroups.keys()])) {
    const left = [...(eslintGroups.get(key) ?? [])];
    const right = [...(oxlintGroups.get(key) ?? [])];
    // Pair findings with the same severity first, then pair what is left as severity mismatches.
    for (let i = left.length - 1; i >= 0; i -= 1) {
      const j = right.findIndex((candidate) => candidate.severity === left[i].severity);
      if (j !== -1) {
        left.splice(i, 1);
        right.splice(j, 1);
      }
    }
    while (left.length > 0 && right.length > 0) severityMismatch.push({ eslint: left.shift(), oxlint: right.shift() });
    onlyEslint.push(...left);
    onlyOxlint.push(...right);
  }

  const used = new Set();
  const isAllowed = (finding) => {
    let allowed = false;
    allowlist.forEach((entry, index) => {
      if (allowMatches(entry, finding)) {
        used.add(index);
        allowed = true;
      }
    });
    return allowed;
  };

  return {
    onlyEslint: onlyEslint.filter((finding) => !isAllowed(finding)),
    onlyOxlint: onlyOxlint.filter((finding) => !isAllowed(finding)),
    severityMismatch: severityMismatch.filter((pair) => !isAllowed(pair.eslint)),
    eslintOnlySkipped,
    staleAllowlist: allowlist.filter((_, index) => !used.has(index)),
  };
};
