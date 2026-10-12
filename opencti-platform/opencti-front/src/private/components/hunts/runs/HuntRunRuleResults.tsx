import React from 'react';
import { graphql, useFragment } from 'react-relay';
import { useTheme } from '@mui/styles';
import { Chip, Text } from '@filigran/design-system';
import Card from '../../../../components/common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { HUNT_DOCS } from '../hunt-utils';
import { HuntLearnMore } from '../HuntLearnMore';
import HuntRunTable, { HuntRunCut, HuntRunDateCell, HuntRunSortValue, sortHuntRunRows, useHuntRunTableSort } from './HuntRunTable';
import { HuntRunRuleResults_run$data, HuntRunRuleResults_run$key } from './__generated__/HuntRunRuleResults_run.graphql';

const huntRunRuleResultsFragment = graphql`
  fragment HuntRunRuleResults_run on HuntRun {
    id
    rule_results {
      key
      title
      status
      hits_count
      truncated
      first_hit_at
      last_hit_at
      error
    }
  }
`;

type RuleResult = NonNullable<HuntRunRuleResults_run$data['rule_results']>[number];

interface RuleRow {
  id: string;
  title: string;
  failed: boolean;
  result: RuleResult;
}

const RULE_SORT_VALUES: Record<string, (row: RuleRow) => HuntRunSortValue> = {
  title: (row) => row.title,
  // A failed rule has no hit count, it sorts with the empty values
  hits_count: (row) => (row.failed ? null : row.result.hits_count),
  first_hit_at: (row) => row.result.first_hit_at,
  last_hit_at: (row) => row.result.last_hit_at,
};

/** What each Sigma rule of a detection-rule hunt run found, a rule that failed to translate or to run failing alone. */
const HuntRunRuleResults = ({ data }: { data: HuntRunRuleResults_run$key }) => {
  const theme = useTheme<Theme>();
  const { t_i18n, n } = useFormatter();
  const run = useFragment(huntRunRuleResultsFragment, data);
  const storageKey = `hunt-run-${run.id}-rules`;
  const sort = useHuntRunTableSort(storageKey, { sortBy: 'hits_count', orderAsc: false });
  const results = run.rule_results ?? [];
  if (results.length === 0) {
    return null;
  }
  const failed = results.filter((result) => result.status !== 'completed').length;
  const matching = results.filter((result) => result.status === 'completed' && result.hits_count > 0).length;
  const rows = sortHuntRunRows(
    results.map((result, index) => ({
      id: result.key,
      title: result.title || t_i18n('Rule {index}', { values: { index: index + 1 } }),
      failed: result.status !== 'completed',
      result,
    })),
    sort.sortBy ? RULE_SORT_VALUES[sort.sortBy] : undefined,
    sort.orderAsc,
  );
  return (
    <Card title={t_i18n('Results per rule')} action={<HuntLearnMore href={HUNT_DOCS.runs} />}>
      <div data-testid="hunt-run-rule-results">
        <Text variant="content-compact-bold" style={{ display: 'block', marginBottom: theme.spacing(1) }} data-testid="hunt-run-rule-summary">
          {t_i18n('{matching} of {count} rules found hits', { values: { matching: n(matching), count: n(results.length) } })}
          {failed > 0 && `, ${t_i18n('{count, plural, one {# rule failed} other {# rules failed}}', { values: { count: failed } })}`}
        </Text>
        <HuntRunTable
          storageKey={storageKey}
          initialValues={sort.initialValues}
          onSort={sort.onSort}
          rows={rows}
          label={t_i18n('Results per rule')}
          testId="hunt-run-rule-table"
          disableNavigation
          dataColumns={{
            title: {
              id: 'title',
              label: 'Rule',
              percentWidth: 52,
              isSortable: true,
              render: (row: RuleRow) => (
                <span
                  style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), minWidth: 0, width: '100%' }}
                  data-testid="hunt-run-rule-row"
                  data-status={row.result.status}
                >
                  {row.failed && <Chip label={t_i18n('Failed')} severity="high" />}
                  <span style={{ display: 'flex', flexDirection: 'column', minWidth: 0 }}>
                    <HuntRunCut value={row.title} />
                    {row.failed && (
                      <Text variant="content-caption" as="span" style={{ display: 'block', minWidth: 0, color: theme.palette.error.main }} data-testid="hunt-run-rule-error">
                        <HuntRunCut value={row.result.error || t_i18n('The rule could not run')} />
                      </Text>
                    )}
                  </span>
                </span>
              ),
            },
            hits_count: {
              id: 'hits_count',
              label: 'Hits',
              percentWidth: 16,
              isSortable: true,
              render: ({ failed: failedRule, result }: RuleRow) => {
                if (failedRule) return '';
                return result.truncated ? t_i18n('At least {count}', { values: { count: n(result.hits_count) } }) : n(result.hits_count);
              },
            },
            first_hit_at: { id: 'first_hit_at', label: 'First hit', percentWidth: 16, isSortable: true, render: ({ result }: RuleRow) => <HuntRunDateCell date={result.first_hit_at} /> },
            last_hit_at: { id: 'last_hit_at', label: 'Last hit', percentWidth: 16, isSortable: true, render: ({ result }: RuleRow) => <HuntRunDateCell date={result.last_hit_at} /> },
          }}
        />
      </div>
    </Card>
  );
};

export default HuntRunRuleResults;
