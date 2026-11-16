/** @typedef {import('./compare.mjs').CompareResult} CompareResult */

const DETAIL_CAP = 50;

/**
 * 1 when any difference list or stale allowlist entry is non-empty.
 * @param {CompareResult} result
 * @returns {0 | 1}
 */
export const exitCode = (result) => (
  result.onlyEslint.length > 0
  || result.onlyOxlint.length > 0
  || result.severityMismatch.length > 0
  || result.staleAllowlist.length > 0 ? 1 : 0
);

const summaryRows = (result) => {
  const rows = new Map();
  const bump = (rule, column) => {
    if (!rows.has(rule)) rows.set(rule, { onlyEslint: 0, onlyOxlint: 0, severityMismatch: 0 });
    rows.get(rule)[column] += 1;
  };
  result.onlyEslint.forEach((finding) => bump(finding.ruleId, 'onlyEslint'));
  result.onlyOxlint.forEach((finding) => bump(finding.ruleId, 'onlyOxlint'));
  result.severityMismatch.forEach((pair) => bump(pair.eslint.ruleId, 'severityMismatch'));
  return [...rows.entries()].sort(([a], [b]) => a.localeCompare(b));
};

const detailGroup = (title, lines) => {
  if (lines.length === 0) return [];
  const shown = lines.slice(0, DETAIL_CAP);
  const rest = lines.length - shown.length;
  return ['', `${title} (${lines.length})`, ...shown.map((line) => `  ${line}`), ...(rest > 0 ? [`  … and ${rest} more`] : [])];
};

const allowEntryLabel = (entry) => `${entry.rule}${entry.files === undefined ? '' : ` (${entry.files})`}`;

/**
 * @param {CompareResult} result
 * @returns {string}
 */
export const formatReport = (result) => {
  const lines = [];
  const rows = summaryRows(result);
  if (rows.length > 0) {
    lines.push('rule | only eslint | only oxlint | severity mismatch');
    rows.forEach(([rule, row]) => lines.push(`${rule} | ${row.onlyEslint} | ${row.onlyOxlint} | ${row.severityMismatch}`));
  }

  const skipped = Object.entries(result.eslintOnlySkipped).sort(([a], [b]) => a.localeCompare(b));
  if (skipped.length > 0) {
    lines.push('', 'ESLint-only findings skipped (rule not compared):');
    skipped.forEach(([rule, count]) => lines.push(`  ${rule}: ${count}`));
  }

  if (result.staleAllowlist.length > 0) {
    lines.push('', 'Stale allowlist entries:');
    result.staleAllowlist.forEach((entry) => lines.push(`  ${allowEntryLabel(entry)} matches no remaining difference — remove it`));
  }

  const at = (finding) => `${finding.file}:${finding.line} ${finding.ruleId}`;
  lines.push(...detailGroup('Only ESLint', result.onlyEslint.map(at)));
  lines.push(...detailGroup('Only oxlint', result.onlyOxlint.map(at)));
  lines.push(...detailGroup(
    'Severity mismatch',
    result.severityMismatch.map((pair) => `${at(pair.eslint)} (eslint ${pair.eslint.severity}, oxlint ${pair.oxlint.severity})`),
  ));

  if (exitCode(result) === 0) lines.unshift('parity: OK');
  else lines.unshift('parity: DIFFERENCES');
  return lines.join('\n');
};
