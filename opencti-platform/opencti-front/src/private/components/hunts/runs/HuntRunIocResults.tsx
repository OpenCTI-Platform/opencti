import React from 'react';
import { graphql, useFragment } from 'react-relay';
import { Link } from 'react-router';
import { useTheme } from '@mui/styles';
import { Chip, Text } from '@filigran/design-system';
import Card from '../../../../components/common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { resolveLink } from '../../../../utils/Entity';
import { iocTypeLabel } from '../hunt-ioc-utils';
import { HUNT_DOCS } from '../hunt-utils';
import { HuntLearnMore } from '../HuntLearnMore';
import { HuntRunIocResults_run$key } from './__generated__/HuntRunIocResults_run.graphql';

const huntRunIocResultsFragment = graphql`
  fragment HuntRunIocResults_run on HuntRun {
    id
    securityPlatform {
      name
    }
    ioc_results {
      key
      observable_type
      hash_algorithm
      value
      verdict
      hits_count
      first_seen
      last_seen
      hosts
      reason
      deployed
      sources {
        id
        entity_type
        representative {
          main
        }
      }
    }
  }
`;

export const huntIocVerdictLabel = (verdict: string) => {
  switch (verdict) {
    case 'seen': return 'Seen';
    case 'not_seen': return 'Not seen';
    case 'not_searched': return 'Not searched';
    default: return 'Pending';
  }
};

export const huntIocVerdictSeverity = (verdict: string) => {
  switch (verdict) {
    case 'seen': return 'critical' as const;
    case 'not_seen': return 'low' as const;
    case 'not_searched': return 'medium' as const;
    default: return 'neutral' as const;
  }
};

const VERDICT_ORDER: Record<string, number> = { seen: 0, not_searched: 1, pending: 2, not_seen: 3 };

/** The result of each value an indicator hunt run looked up: seen or not, hits, first and last seen, hosts. */
const HuntRunIocResults = ({ data }: { data: HuntRunIocResults_run$key }) => {
  const theme = useTheme<Theme>();
  const { t_i18n, n, fldt } = useFormatter();
  const run = useFragment(huntRunIocResultsFragment, data);
  const results = [...(run.ioc_results ?? [])];
  if (results.length === 0) {
    return null;
  }
  results.sort((a, b) => (VERDICT_ORDER[a.verdict] ?? 9) - (VERDICT_ORDER[b.verdict] ?? 9) || b.hits_count - a.hits_count);
  const count = (verdict: string) => results.filter((result) => result.verdict === verdict).length;
  const platform = run.securityPlatform?.name ?? '';
  const cell = { padding: theme.spacing(0.75), verticalAlign: 'top' as const, borderBottom: `1px solid ${theme.palette.divider}` };
  return (
    <Card title={t_i18n('Results per value')} action={<HuntLearnMore href={HUNT_DOCS.indicatorResults} testId="hunt-run-ioc-learn-more" />}>
      <div data-testid="hunt-run-ioc-results">
        <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), flexWrap: 'wrap', marginBottom: theme.spacing(1) }}>
          <Text variant="content-compact-bold" data-testid="hunt-run-ioc-summary">
            {t_i18n('{seen} of {count} values seen on {platform}', { values: { seen: n(count('seen')), count: n(results.length), platform } })}
          </Text>
          {['seen', 'not_seen', 'not_searched'].filter((verdict) => count(verdict) > 0).map((verdict) => (
            <Chip key={verdict} label={`${t_i18n(huntIocVerdictLabel(verdict))}: ${n(count(verdict))}`} severity={huntIocVerdictSeverity(verdict)} />
          ))}
        </div>
        {count('not_searched') > 0 && (
          <Text variant="content-caption" style={{ display: 'block', marginBottom: theme.spacing(1), color: theme.palette.text.secondary }}>
            {t_i18n('A run with values not searched proves nothing about them: without hits, its verdict is inconclusive.')}
          </Text>
        )}
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                {[t_i18n('Value'), t_i18n('Verdict'), t_i18n('Hits'), t_i18n('First seen'), t_i18n('Last seen'), t_i18n('Hosts'), t_i18n('From')].map((header) => (
                  <th key={header} scope="col" style={{ ...cell, textAlign: 'left' }}><Text variant="content-caption">{header}</Text></th>
                ))}
              </tr>
            </thead>
            <tbody>
              {results.map((result) => (
                <tr key={result.key} data-testid="hunt-run-ioc-row" data-verdict={result.verdict}>
                  <td style={{ ...cell, wordBreak: 'break-all', minWidth: 180 }}>
                    <Text variant="content-compact">{result.value}</Text>
                    <Text variant="content-caption" style={{ display: 'block', color: theme.palette.text.secondary }}>{iocTypeLabel(result.observable_type, t_i18n, result.hash_algorithm)}</Text>
                  </td>
                  <td style={cell}>
                    <Chip label={t_i18n(huntIocVerdictLabel(result.verdict))} severity={huntIocVerdictSeverity(result.verdict)} />
                    {result.reason && <Text variant="content-caption" style={{ display: 'block', marginTop: theme.spacing(0.5), color: theme.palette.text.secondary }}>{result.reason}</Text>}
                  </td>
                  <td style={cell}><Text variant="content-compact">{result.verdict === 'seen' ? n(result.hits_count) : '-'}</Text></td>
                  <td style={cell}><Text variant="content-compact">{result.first_seen ? fldt(result.first_seen) : '-'}</Text></td>
                  <td style={cell}><Text variant="content-compact">{result.last_seen ? fldt(result.last_seen) : '-'}</Text></td>
                  <td style={cell}>
                    {result.hosts.length > 0
                      ? <div style={{ display: 'flex', flexWrap: 'wrap', gap: theme.spacing(0.5) }}>{result.hosts.map((host) => <Chip key={host} label={host} />)}</div>
                      : <Text variant="content-compact">-</Text>}
                  </td>
                  <td style={cell}>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: theme.spacing(0.5) }}>
                      {result.sources.length === 0 && <Text variant="content-caption" style={{ color: theme.palette.text.secondary }}>{t_i18n('Pasted value')}</Text>}
                      {result.sources.map((source) => (
                        <Link key={source.id} to={`${resolveLink(source.entity_type)}/${source.id}`}>
                          <Chip label={source.representative.main} />
                        </Link>
                      ))}
                      {result.deployed && <Chip label={t_i18n('Deployed on this platform')} severity="info" data-testid="hunt-run-ioc-deployed" />}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </Card>
  );
};

export default HuntRunIocResults;
