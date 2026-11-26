import React, { FunctionComponent } from 'react';
import { CheckCircleOutlined, DownloadOutlined } from '@mui/icons-material';
import { useTheme } from '@mui/material/styles';
import { ProgressBar, Spinner, Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import { APP_BASE_PATH } from '../../../../../relay/environment';
import { useResultLabel } from './ConfigPresetResultGroups';
import ConfigPresetResultLine, { CODE_UNCHANGED } from './ConfigPresetResultLine';
import type { ConfigPresetImportSession } from './ConfigPresetImportWizard';

interface ConfigPresetImportProgressProps {
  session: ConfigPresetImportSession | null;
}

type TypeCounts = ConfigPresetImportSession['type_counts'][number];
type Problem = ConfigPresetImportSession['problems'][number];

// The first problems of a run are listed, the rest is in the report: a bundle where every item fails stays as light as one where none does
export const ProblemsList: FunctionComponent<{ problems: ReadonlyArray<Problem>; problemsCount: number; hasReport: boolean }> = ({ problems, problemsCount, hasReport }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const resultLabel = useResultLabel();
  if (problems.length === 0) {
    return null;
  }
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1) }}>
      <Text variant="title-sm">{t_i18n('Items to check ({count})', { values: { count: problemsCount } })}</Text>
      {problems.map((problem) => (
        <ConfigPresetResultLine
          key={`${problem.type}/${problem.key}`}
          label={`${t_i18n(problem.type_label)}: ${resultLabel(problem)}`}
          status={problem.status}
          reason={problem.reason}
          code={problem.code}
        />
      ))}
      {problemsCount > problems.length && (
        <Text variant="content-base">
          {hasReport
            ? t_i18n('The first {shown} of {count} are listed. The report holds the complete list.', { values: { shown: problems.length, count: problemsCount } })
            : t_i18n('The first {shown} of {count} are listed.', { values: { shown: problems.length, count: problemsCount } })}
        </Text>
      )}
    </div>
  );
};

const sumTypeCounts = (typeCounts: ReadonlyArray<TypeCounts>) => typeCounts.reduce(
  (total, counts) => ({
    created: total.created + counts.created,
    overwritten: total.overwritten + counts.overwritten,
    unchanged: total.unchanged + counts.unchanged,
    skipped: total.skipped + counts.skipped,
    failed: total.failed + counts.failed,
  }),
  { created: 0, overwritten: 0, unchanged: 0, skipped: 0, failed: 0 },
);

// The items that need a look: what failed, or was skipped for a reason. What the platform had as it is does not.
export const countProblems = (typeCounts: ReadonlyArray<TypeCounts>) => {
  const { skipped, failed } = sumTypeCounts(typeCounts);
  return skipped + failed;
};

// The import of the user runs: how far it is, the last items processed and the problems so far, from the session
export const ConfigPresetImportProgress: FunctionComponent<ConfigPresetImportProgressProps> = ({ session }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const resultLabel = useResultLabel();
  const processed = session?.processed ?? 0;
  const total = session?.total ?? 0;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1.5) }}>
      <Spinner label={t_i18n('Import in progress')} />
      {total > 0 && (
        <>
          <ProgressBar aria-label={t_i18n('Import progress')} value={(processed / total) * 100} size="lg" />
          <Text variant="content-base">{t_i18n('{processed} of {total} items processed', { values: { processed, total } })}</Text>
        </>
      )}
      <ProblemsList problems={session?.problems ?? []} problemsCount={countProblems(session?.type_counts ?? [])} hasReport={false} />
      {(session?.recent ?? []).map((result) => (
        <ConfigPresetResultLine key={`${result.type}/${result.key}`} label={resultLabel(result)} status={result.status} reason={result.reason} code={result.code} />
      ))}
    </div>
  );
};

interface ConfigPresetImportResultProps {
  session: ConfigPresetImportSession;
  // Clears the session and closes the wizard
  onClose: () => void;
}

interface ConfigPresetImportCounts {
  readonly created: number;
  readonly overwritten: number;
  readonly skipped: number;
  readonly failed: number;
}

// The items the platform already had as they are are counted apart: the backend counts them as skipped, which reads as if they were ignored.
// Shared by the result of the wizard and the one of a partial import
export const toConfigPresetSummaryCounts = (
  counts: ConfigPresetImportCounts | null | undefined,
  results: ReadonlyArray<{ readonly status: string; readonly code?: string | null }>,
) => {
  if (!counts) {
    return null;
  }
  const unchanged = Math.min(counts.skipped, results.filter((result) => result.status === 'SKIPPED' && result.code === CODE_UNCHANGED).length);
  return { ...counts, skipped: counts.skipped - unchanged, unchanged };
};

// What the import did with the items of a type, in words: only what happened
const useCountsText = () => {
  const { t_i18n } = useFormatter();
  return (counts: Omit<TypeCounts, 'type' | 'type_label' | 'type_index' | 'group'>) => [
    counts.created > 0 && t_i18n('{count} created', { values: { count: counts.created } }),
    counts.overwritten > 0 && t_i18n('{count} overwritten', { values: { count: counts.overwritten } }),
    counts.unchanged > 0 && t_i18n('{count} up to date', { values: { count: counts.unchanged } }),
    counts.skipped > 0 && t_i18n('{count} skipped', { values: { count: counts.skipped } }),
    counts.failed > 0 && t_i18n('{count} failed', { values: { count: counts.failed } }),
  ].filter(Boolean).join(', ');
};

// The types of the import by group, in the order of the selection, each with what the import did with its items
export const TypeCountsByGroup: FunctionComponent<{ typeCounts: ReadonlyArray<TypeCounts> }> = ({ typeCounts }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const countsText = useCountsText();
  const groups = new Map<string, { label: string; types: TypeCounts[] }>();
  [...typeCounts].sort((a, b) => a.type_index - b.type_index).forEach((counts) => {
    const group = groups.get(counts.group.key) ?? { label: counts.group.label, types: [] };
    group.types.push(counts);
    groups.set(counts.group.key, group);
  });
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1.5) }}>
      {[...groups.entries()].map(([key, group]) => (
        <div key={key} style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(0.5) }}>
          <Text variant="title-sm">{t_i18n(group.label)}</Text>
          {group.types.map((counts) => {
            // Done when something was imported in it and nothing failed or was refused
            const isDone = counts.failed === 0 && counts.skipped === 0 && counts.created + counts.overwritten > 0;
            return (
              <div key={counts.type} style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
                {isDone && <CheckCircleOutlined aria-hidden data-testid="config-preset-result-tick" fontSize="small" style={{ color: theme.palette.success.main }} />}
                <Text variant="content-base">{`${t_i18n(counts.type_label)}: ${countsText(counts)}`}</Text>
              </div>
            );
          })}
        </div>
      ))}
    </div>
  );
};

// The result of the last import: what was done by type, what needs a look, and the report to download for the rest. The items that went
// well are not listed: tens of thousands of lines of "created" tell nothing, and the report holds them.
export const ConfigPresetImportResult: FunctionComponent<ConfigPresetImportResultProps> = ({ session, onClose }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const total = sumTypeCounts(session.type_counts);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1.5) }}>
      <Text variant="title-sm">{t_i18n('Import finished')}</Text>
      <Text variant="content-base">
        {t_i18n('{created} created, {overwritten} overwritten, {unchanged} up to date, {skipped} skipped, {failed} failed', { values: total })}
      </Text>
      <TypeCountsByGroup typeCounts={session.type_counts} />
      <ProblemsList problems={session.problems} problemsCount={countProblems(session.type_counts)} hasReport={!!session.report_id} />
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: theme.spacing(1) }}>
        {session.report_id && (
          <Button
            variant="secondary"
            component="a"
            href={`${APP_BASE_PATH}/storage/get/${encodeURIComponent(session.report_id)}`}
            startIcon={<DownloadOutlined />}
          >
            {t_i18n('Download report')}
          </Button>
        )}
        <Button onClick={onClose}>{t_i18n('Close')}</Button>
      </div>
    </div>
  );
};
