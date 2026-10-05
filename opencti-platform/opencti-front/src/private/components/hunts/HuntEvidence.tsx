import React, { Suspense, useMemo, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { useTheme } from '@mui/styles';
import { Input, Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Text } from '@filigran/design-system';
import DataTableWithoutFragment from '../../../components/dataGrid/DataTableWithoutFragment';
import { DataTableVariant } from '../../../components/dataGrid/dataTableTypes';
import { defaultRender } from '../../../components/dataGrid/dataTableUtils';
import Loader, { LoaderVariant } from '../../../components/Loader';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import { PATH_HUNT } from '../common/routes/paths';
import { aggregateHuntEvidence, huntEvidenceFields, huntEvidenceWindow, shortHash, type HuntEvidenceRow } from './hunt-evidence-utils';
import { HUNT_DOCS, HUNT_RUN_ENTITY_TYPE } from './hunt-utils';
import { HuntHelp } from './HuntLearnMore';
import { HuntEvidenceRunsQuery, HuntEvidenceRunsQuery$variables } from './__generated__/HuntEvidenceRunsQuery.graphql';

/** The evidence of the most recent completed runs is aggregated in the browser; the screen names this window when older runs exist. */
const EVIDENCE_RUNS_COUNT = 100;
const ALL = 'all';

const huntEvidenceRunsQuery = graphql`
  query HuntEvidenceRunsQuery($filters: FilterGroup, $count: Int!) {
    huntRuns(first: $count, orderBy: completed_at, orderMode: desc, filters: $filters) {
      edges {
        node {
          id
          created_at
          completed_at
          hits_count
          securityPlatform {
            id
            name
          }
          connector_name
          evidence_sample {
            field
            value_hash
            value_preview
            count
          }
        }
      }
      pageInfo {
        globalCount
      }
    }
  }
`;

const HuntEvidenceComponent = ({ huntId }: { huntId: string }) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fldt, n } = useFormatter();
  const [runId, setRunId] = useState<string>(ALL);
  const [field, setField] = useState<string>(ALL);
  const [search, setSearch] = useState('');
  const filters: HuntEvidenceRunsQuery$variables['filters'] = {
    mode: 'and',
    filters: [
      { key: ['entity_type'], values: [HUNT_RUN_ENTITY_TYPE], operator: 'eq', mode: 'or' },
      { key: ['hunt_id'], values: [huntId], operator: 'eq', mode: 'or' },
      { key: ['hunt_run_mode'], values: ['execute'], operator: 'eq', mode: 'or' },
      { key: ['hunt_run_status'], values: ['completed'], operator: 'eq', mode: 'or' },
    ],
    filterGroups: [],
  };
  const { huntRuns } = useLazyLoadQuery<HuntEvidenceRunsQuery>(
    huntEvidenceRunsQuery,
    { filters, count: EVIDENCE_RUNS_COUNT },
    { fetchPolicy: 'store-and-network' },
  );
  const runs = useMemo(() => (huntRuns?.edges ?? []).map(({ node }) => ({
    id: node.id,
    created_at: node.created_at,
    completed_at: node.completed_at,
    platform: node.securityPlatform?.name ?? node.connector_name ?? null,
    evidence_sample: node.evidence_sample,
  })), [huntRuns]);
  const fields = useMemo(() => huntEvidenceFields(runs), [runs]);
  const rows = useMemo(() => aggregateHuntEvidence(runs, {
    runIds: runId === ALL ? [] : [runId],
    field: field === ALL ? null : field,
    search,
  }), [runs, runId, field, search]);

  if (runs.length === 0) {
    return (
      <div data-testid="hunt-evidence-empty">
        <Text variant="content-compact">{t_i18n('No completed run of this hunt has reported evidence yet')}</Text>
        <Text variant="content-caption" style={{ display: 'block', marginTop: theme.spacing(0.5), color: theme.palette.text.secondary }}>
          <HuntHelp
            text={t_i18n('Evidence is the sample of hashed values a completed run reports, for example the hosts and command lines its query matched. Run the hunt to collect it.')}
            href={HUNT_DOCS.runs}
          />
        </Text>
      </div>
    );
  }
  const { completedRunsCount, isWindowed, since } = huntEvidenceWindow(runs, huntRuns?.pageInfo?.globalCount);
  const dateRender = (value: string | null) => defaultRender(value ? fldt(value) : '-');
  return (
    <>
      <div style={{ display: 'flex', gap: theme.spacing(1.5), flexWrap: 'wrap', alignItems: 'center', marginBottom: theme.spacing(2) }} data-testid="hunt-evidence-filters">
        <Select value={runId} onValueChange={setRunId}>
          <SelectTrigger aria-label={t_i18n('Hunt run')} style={{ minWidth: 260 }}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Hunt run')}>
            <SelectItem value={ALL}>
              {isWindowed
                ? t_i18n('Latest {count} of {total} runs', { values: { count: n(runs.length), total: n(completedRunsCount) } })
                : t_i18n('All runs ({count})', { values: { count: runs.length } })}
            </SelectItem>
            {runs.map((run) => (
              <SelectItem key={run.id} value={run.id}>
                {`${fldt(run.completed_at ?? run.created_at)} - ${run.platform ?? t_i18n('Internet')}`}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={field} onValueChange={setField}>
          <SelectTrigger aria-label={t_i18n('Field')} style={{ minWidth: 200 }}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Field')}>
            <SelectItem value={ALL}>{t_i18n('All fields')}</SelectItem>
            {fields.map((name) => <SelectItem key={name} value={name}>{name}</SelectItem>)}
          </SelectContent>
        </Select>
        <Input
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder={t_i18n('Search a value')}
          aria-label={t_i18n('Search a value')}
          style={{ minWidth: 240 }}
        />
        <Text variant="content-caption">{t_i18n('{count} distinct values', { values: { count: n(rows.length) } })}</Text>
      </div>
      {isWindowed && (
        <div style={{ marginBottom: theme.spacing(2) }} data-testid="hunt-evidence-window">
          <Text variant="content-caption">
            {t_i18n('Evidence of the {count} most recent completed runs, since {date}. Each older run keeps its evidence on its page in the Runs tab.', {
              values: { count: n(runs.length), date: since ? fldt(since) : '-' },
            })}
          </Text>
        </div>
      )}
      <div data-testid="hunt-evidence-table">
        <DataTableWithoutFragment
          storageKey={`hunt-${huntId}-evidence`}
          variant={DataTableVariant.inline}
          data={rows}
          globalCount={rows.length}
          disableLineSelection
          disableToolBar
          removeSelectAll
          emptyStateMessage={t_i18n('No evidence matches these filters')}
          dataColumns={{
            field: { id: 'field', label: 'Field', percentWidth: 16, isSortable: false, render: ({ field: name }: HuntEvidenceRow) => defaultRender(name) },
            value_preview: { id: 'value_preview', label: 'Value', percentWidth: 28, isSortable: false, render: ({ value_preview }: HuntEvidenceRow) => defaultRender(value_preview ?? '-') },
            value_hash: { id: 'value_hash', label: 'Hash', percentWidth: 12, isSortable: false, render: ({ value_hash }: HuntEvidenceRow) => defaultRender(shortHash(value_hash)) },
            count: { id: 'count', label: 'Count', percentWidth: 8, isSortable: false, render: ({ count }: HuntEvidenceRow) => defaultRender(n(count)) },
            runs_count: { id: 'runs_count', label: 'Runs', percentWidth: 8, isSortable: false, render: ({ runs_count }: HuntEvidenceRow) => defaultRender(n(runs_count)) },
            platforms: { id: 'platforms', label: 'Platforms', percentWidth: 12, isSortable: false, render: ({ platforms }: HuntEvidenceRow) => defaultRender(platforms.join(', ') || '-') },
            first_seen_at: { id: 'first_seen_at', label: 'First seen', percentWidth: 8, isSortable: false, render: ({ first_seen_at }: HuntEvidenceRow) => dateRender(first_seen_at) },
            last_seen_at: { id: 'last_seen_at', label: 'Last seen', percentWidth: 8, isSortable: false, render: ({ last_seen_at }: HuntEvidenceRow) => dateRender(last_seen_at) },
          }}
          getComputeLink={(row: HuntEvidenceRow) => (row.run_ids.length === 1 ? `${PATH_HUNT(huntId)}/runs/${row.run_ids[0]}` : undefined)}
        />
      </div>
    </>
  );
};

const HuntEvidence = ({ huntId }: { huntId: string }) => (
  <div data-testid="hunt-evidence-page">
    <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <HuntEvidenceComponent huntId={huntId} />
    </Suspense>
  </div>
);

export default HuntEvidence;
