import React from 'react';
import { graphql, useFragment } from 'react-relay';
import { useTheme } from '@mui/styles';
import { Chip, Text, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Card from '../../../../components/common/card/Card';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { resolveLink } from '../../../../utils/Entity';
import { iocTypeLabel } from '../hunt-ioc-utils';
import { HUNT_DOCS } from '../hunt-utils';
import { HuntLearnMore } from '../HuntLearnMore';
import HuntRunTable, { HuntRunCut, HuntRunDateCell, HuntRunSortValue, sortHuntRunRows, useHuntRunTableSort } from './HuntRunTable';
import { HuntRunIocResults_run$data, HuntRunIocResults_run$key } from './__generated__/HuntRunIocResults_run.graphql';

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

// The hosts a cell names before it counts the others
const HOSTS_SHOWN = 2;

type IocResult = NonNullable<HuntRunIocResults_run$data['ioc_results']>[number];

interface IocRow {
  id: string;
  result: IocResult;
}

const dateValue = (date?: string | null) => (date ? new Date(date).getTime() : null);

const IOC_SORT_VALUES: Record<string, (row: IocRow) => HuntRunSortValue> = {
  value: (row) => row.result.value,
  verdict: (row) => VERDICT_ORDER[row.result.verdict] ?? 9,
  // Only a value seen has hits, the others sort with the empty values
  hits_count: (row) => (row.result.verdict === 'seen' ? row.result.hits_count : null),
  first_seen: (row) => dateValue(row.result.first_seen),
  last_seen: (row) => dateValue(row.result.last_seen),
};

/** The result of each value an indicator hunt run looked up: seen or not, hits, first and last seen, hosts. */
const HuntRunIocResults = ({ data }: { data: HuntRunIocResults_run$key }) => {
  const theme = useTheme<Theme>();
  const { t_i18n, n } = useFormatter();
  const run = useFragment(huntRunIocResultsFragment, data);
  const storageKey = `hunt-run-${run.id}-values`;
  const sort = useHuntRunTableSort(storageKey, { sortBy: 'verdict', orderAsc: true });
  const results = [...(run.ioc_results ?? [])];
  if (results.length === 0) {
    return null;
  }
  // Values that tie on the sorted column keep this order: by verdict, then the most hits first
  results.sort((a, b) => (VERDICT_ORDER[a.verdict] ?? 9) - (VERDICT_ORDER[b.verdict] ?? 9) || b.hits_count - a.hits_count);
  const rows = sortHuntRunRows(results.map((result) => ({ id: result.key, result })), sort.sortBy ? IOC_SORT_VALUES[sort.sortBy] : undefined, sort.orderAsc);
  const count = (verdict: string) => results.filter((result) => result.verdict === verdict).length;
  const platform = run.securityPlatform?.name ?? '';
  const secondary = { color: theme.palette.text.secondary };
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
          <Text variant="content-caption" style={{ display: 'block', marginBottom: theme.spacing(1), ...secondary }}>
            {t_i18n('A run with values not searched proves nothing about them: without hits, its verdict is inconclusive.')}
          </Text>
        )}
        <HuntRunTable
          storageKey={storageKey}
          initialValues={sort.initialValues}
          onSort={sort.onSort}
          rows={rows}
          label={t_i18n('Results per value')}
          testId="hunt-run-ioc-table"
          getComputeLink={({ result }: IocRow) => {
            const [source] = result.sources;
            if (!source) return undefined;
            const route = resolveLink(source.entity_type);
            return route ? `${route}/${source.id}` : undefined;
          }}
          dataColumns={{
            value: {
              id: 'value',
              label: 'Value',
              percentWidth: 26,
              isSortable: true,
              render: ({ result }: IocRow) => (
                <span style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), minWidth: 0 }} data-testid="hunt-run-ioc-row" data-verdict={result.verdict}>
                  <ItemIcon type={result.observable_type} size="small" />
                  <span style={{ display: 'flex', flexDirection: 'column', minWidth: 0 }}>
                    <HuntRunCut value={result.value} />
                    <Text variant="content-caption" as="span" style={{ display: 'block', minWidth: 0, ...secondary }}>
                      <HuntRunCut value={iocTypeLabel(result.observable_type, t_i18n, result.hash_algorithm)} />
                    </Text>
                  </span>
                </span>
              ),
            },
            verdict: {
              id: 'verdict',
              label: 'Verdict',
              percentWidth: 12,
              isSortable: true,
              render: ({ result }: IocRow) => {
                const chip = <Chip label={t_i18n(huntIocVerdictLabel(result.verdict))} severity={huntIocVerdictSeverity(result.verdict)} />;
                if (!result.reason) return chip;
                return (
                  <Tooltip>
                    <TooltipTrigger asChild>
                      {/* rounded-sm is the radius of the chip, so the focus ring follows its shape */}
                      <span
                        tabIndex={0}
                        className="inline-flex rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-filigran-brand-primary focus-visible:ring-offset-2 focus-visible:ring-offset-focus"
                        data-testid="hunt-run-ioc-reason"
                      >
                        {chip}
                      </span>
                    </TooltipTrigger>
                    <TooltipContent>{result.reason}</TooltipContent>
                  </Tooltip>
                );
              },
            },
            hits_count: {
              id: 'hits_count',
              label: 'Hits',
              percentWidth: 8,
              isSortable: true,
              render: ({ result }: IocRow) => (result.verdict === 'seen' ? n(result.hits_count) : ''),
            },
            hosts: {
              id: 'hosts',
              label: 'Hosts',
              percentWidth: 16,
              isSortable: false,
              render: ({ result }: IocRow) => {
                if (result.hosts.length === 0) return '';
                const items = result.hosts.slice(0, HOSTS_SHOWN).join(', ');
                const value = result.hosts.length > HOSTS_SHOWN
                  ? t_i18n('{items} and {count} more', { values: { items, count: n(result.hosts.length - HOSTS_SHOWN) } })
                  : items;
                return <HuntRunCut value={value} full={result.hosts.join(', ')} />;
              },
            },
            first_seen: { id: 'first_seen', label: 'First seen', percentWidth: 11, isSortable: true, render: ({ result }: IocRow) => <HuntRunDateCell date={result.first_seen} /> },
            last_seen: { id: 'last_seen', label: 'Last seen', percentWidth: 11, isSortable: true, render: ({ result }: IocRow) => <HuntRunDateCell date={result.last_seen} /> },
            sources: {
              id: 'sources',
              label: 'From',
              percentWidth: 16,
              isSortable: false,
              render: ({ result }: IocRow) => {
                const [source] = result.sources;
                return (
                  <span style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(0.5), minWidth: 0 }}>
                    {source ? (
                      <>
                        <ItemIcon type={source.entity_type} size="small" />
                        <HuntRunCut value={result.sources.map(({ representative }) => representative.main).join(', ')} />
                      </>
                    ) : (
                      <Text variant="content-caption" as="span" style={secondary}>{t_i18n('Pasted value')}</Text>
                    )}
                    {result.deployed && <Chip label={t_i18n('Deployed on this platform')} severity="info" data-testid="hunt-run-ioc-deployed" />}
                  </span>
                );
              },
            },
          }}
        />
      </div>
    </Card>
  );
};

export default HuntRunIocResults;
