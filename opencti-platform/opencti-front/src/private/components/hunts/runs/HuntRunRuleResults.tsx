import React from 'react';
import { graphql, useFragment } from 'react-relay';
import { useTheme } from '@mui/styles';
import { Chip, Text } from '@filigran/design-system';
import Card from '../../../../components/common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { HUNT_DOCS } from '../hunt-utils';
import { HuntLearnMore } from '../HuntLearnMore';
import { HuntRunRuleResults_run$key } from './__generated__/HuntRunRuleResults_run.graphql';

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

/** What each Sigma rule of a detection-rule hunt run found, a rule that failed to translate or to run failing alone. */
const HuntRunRuleResults = ({ data }: { data: HuntRunRuleResults_run$key }) => {
  const theme = useTheme<Theme>();
  const { t_i18n, n, fldt } = useFormatter();
  const run = useFragment(huntRunRuleResultsFragment, data);
  const results = run.rule_results ?? [];
  if (results.length === 0) {
    return null;
  }
  const failed = results.filter((result) => result.status !== 'completed').length;
  const matching = results.filter((result) => result.status === 'completed' && result.hits_count > 0).length;
  const cell = { padding: theme.spacing(0.75), verticalAlign: 'top' as const, borderBottom: `1px solid ${theme.palette.divider}` };
  return (
    <Card title={t_i18n('Results per rule')} action={<HuntLearnMore href={HUNT_DOCS.runs} />}>
      <div data-testid="hunt-run-rule-results">
        <Text variant="content-compact-bold" style={{ display: 'block', marginBottom: theme.spacing(1) }} data-testid="hunt-run-rule-summary">
          {t_i18n('{matching} of {count} rules found hits', { values: { matching: n(matching), count: n(results.length) } })}
          {failed > 0 && `, ${t_i18n('{count, plural, one {# rule failed} other {# rules failed}}', { values: { count: failed } })}`}
        </Text>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                {[t_i18n('Rule'), t_i18n('Hits'), t_i18n('First hit'), t_i18n('Last hit')].map((header) => (
                  <th key={header} scope="col" style={{ ...cell, textAlign: 'left' }}><Text variant="content-caption">{header}</Text></th>
                ))}
              </tr>
            </thead>
            <tbody>
              {results.map((result, index) => {
                const failedRule = result.status !== 'completed';
                return (
                  <tr key={result.key} data-testid="hunt-run-rule-row" data-status={result.status}>
                    <td style={{ ...cell, minWidth: 220 }}>
                      <Text variant="content-compact">{result.title || t_i18n('Rule {index}', { values: { index: index + 1 } })}</Text>
                      {failedRule && (
                        <Text variant="content-caption" style={{ display: 'block', color: theme.palette.error.main }} data-testid="hunt-run-rule-error">
                          {result.error || t_i18n('The rule could not run')}
                        </Text>
                      )}
                    </td>
                    <td style={cell}>
                      {failedRule ? <Chip label={t_i18n('Failed')} severity="high" /> : (
                        <Text variant="content-compact">
                          {result.truncated ? t_i18n('At least {count}', { values: { count: n(result.hits_count) } }) : n(result.hits_count)}
                        </Text>
                      )}
                    </td>
                    <td style={cell}><Text variant="content-compact">{result.first_hit_at ? fldt(result.first_hit_at) : '-'}</Text></td>
                    <td style={cell}><Text variant="content-compact">{result.last_hit_at ? fldt(result.last_hit_at) : '-'}</Text></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </Card>
  );
};

export default HuntRunRuleResults;
