import React, { Suspense, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Chip, Text } from '@filigran/design-system';
import Box from '@mui/material/Box';
import Button from '@common/button/Button';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import DataTable from '../../../../components/dataGrid/DataTable';
import type { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useEntityToggle from '../../../../utils/hooks/useEntityToggle';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { useQueryLoadingWithLoadQuery } from '../../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { criterionName, explanationText, IN_STATUSES, ScoreBar, StatusChip } from './IrOutputCommon';
import IrMatchDrawer, { type IrMatchData } from './IrMatchDrawer';
import { IrTriageCard, type IrTriageVerdict, runTriage, useIrTriageAgent, VERDICT_CHIPS } from './IrTriage';
import type { IrEntitiesLinesQuery, IrEntitiesLinesQuery$variables } from './__generated__/IrEntitiesLinesQuery.graphql';
import type { IrEntities_data$data } from './__generated__/IrEntities_data.graphql';
import type { IrEntitiesLine_node$data } from './__generated__/IrEntitiesLine_node.graphql';
import type { IrEntitiesRequirementQuery } from './__generated__/IrEntitiesRequirementQuery.graphql';
import type { IrEntitiesBulkStatusMutation } from './__generated__/IrEntitiesBulkStatusMutation.graphql';
import type { IrEntitiesTypesQuery } from './__generated__/IrEntitiesTypesQuery.graphql';

// ① Entities of the requirement, as a standard data table: status presets, filters, sort and pagination on the server,
// bulk decisions and bulk AI opinions on the selection, details in the drawer.

const ENTITY_TYPE = 'IntelligenceRequirementMatch';
const MAX_BULK_TRIAGE = 15;

const requirementQuery = graphql`
  query IrEntitiesRequirementQuery($id: ID!) {
    intelligenceRequirement(id: $id) {
      id
      ir_inbox_open_count
      ir_scope_criteria { id name kind }
      ir_kiqs { id criteria_ids }
    }
  }
`;

const typesQuery = graphql`
  query IrEntitiesTypesQuery($id: ID!, $statuses: [IrMatchStatus!], $excluded: Boolean) {
    intelligenceRequirement(id: $id) {
      id
      ir_inbox_open_count
      ir_entities_by_type(statuses: $statuses, excluded: $excluded) { entity_type count }
    }
  }
`;

// Quick type filters: one chip per type present in the current status preset, with its count
const TypeFilters = ({ irId, statuses, excluded, value, onChange, fetchKey }: {
  irId: string;
  statuses: string[];
  excluded?: boolean;
  value: string | null;
  onChange: (type: string | null) => void;
  fetchKey: number;
}) => {
  const { t_i18n } = useFormatter();
  const data = useLazyLoadQuery<IrEntitiesTypesQuery>(
    typesQuery,
    { id: irId, statuses: statuses as IrEntitiesTypesQuery['variables']['statuses'], excluded: excluded ?? null },
    { fetchPolicy: 'store-and-network', fetchKey },
  );
  const counts = data.intelligenceRequirement?.ir_entities_by_type ?? [];
  const total = counts.reduce((sum, c) => sum + c.count, 0);
  return (
    <Box sx={{ display: 'flex', gap: 0.75, flexWrap: 'wrap', alignItems: 'center', justifyContent: 'flex-end', flex: 1, minWidth: 0 }}>
      <Button size="small" variant={value === null ? 'primary' : 'tertiary'} onClick={() => onChange(null)}>{`${t_i18n('All')} (${total})`}</Button>
      {counts.map((c) => (
        <Button key={c.entity_type} size="small" variant={value === c.entity_type ? 'primary' : 'tertiary'} onClick={() => onChange(c.entity_type)}>
          {`${t_i18n(`entity_${c.entity_type}`)} (${c.count})`}
        </Button>
      ))}
      {value && !counts.some((c) => c.entity_type === value) && (
        <Button size="small" variant="primary" onClick={() => onChange(null)}>{`${t_i18n(`entity_${value}`)} (0)`}</Button>
      )}
    </Box>
  );
};

export const irEntitiesLineFragment = graphql`
  fragment IrEntitiesLine_node on IntelligenceRequirementMatch {
    id
    entity_type
    match_entity_id
    match_entity_name
    match_entity_type
    match_status
    match_score
    match_excluded
    match_criteria_ids
    match_last_fact_at
    created_at
    entity { ... on StixCoreObject { representative { main } } }
    match_explanations {
      criterion_id
      kind
      relationship_type
      direction
      keyword
      field
      anchor { representative { main } }
      container { representative { main } }
    }
    match_score_breakdown { name points hit reason kind criterion_id }
  }
`;

export const irEntitiesLinesFragment = graphql`
  fragment IrEntities_data on Query
  @argumentDefinitions(
    id: { type: "ID!" }
    statuses: { type: "[IrMatchStatus!]" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "IntelligenceRequirementMatchOrdering", defaultValue: match_score }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "IrEntitiesRefetchQuery") {
    intelligenceRequirementMatches(
      id: $id
      statuses: $statuses
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_intelligenceRequirementMatches") {
      edges {
        node {
          id
          ...IrEntitiesLine_node
        }
      }
      pageInfo {
        endCursor
        hasNextPage
        globalCount
      }
    }
  }
`;

export const irEntitiesLinesQuery = graphql`
  query IrEntitiesLinesQuery(
    $id: ID!
    $statuses: [IrMatchStatus!]
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: IntelligenceRequirementMatchOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...IrEntities_data
    @arguments(
      id: $id
      statuses: $statuses
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

const bulkStatusMutation = graphql`
  mutation IrEntitiesBulkStatusMutation($ids: [ID!]!, $status: IrMatchDecisionStatus!) {
    intelligenceRequirementMatchesStatusUpdate(ids: $ids, status: $status)
  }
`;

type Preset = 'in' | 'proposed' | 'excluded' | 'closed';
type Decision = 'accepted' | 'rejected' | 'removed';
type Line = IrEntitiesLine_node$data;

const PRESETS: { value: Preset; label: string; statuses: string[]; excluded?: boolean }[] = [
  { value: 'in', label: 'In the requirement', statuses: IN_STATUSES, excluded: false },
  { value: 'proposed', label: 'Proposed', statuses: ['proposed'] },
  { value: 'excluded', label: 'Accepted, no longer meeting the scope conditions', statuses: IN_STATUSES, excluded: true },
  { value: 'closed', label: 'Rejected or removed', statuses: ['rejected', 'removed'] },
];
// A decision applies to the entities in these statuses (same rule as the server)
const DECISION_FROM: Record<Decision, string[]> = { accepted: ['proposed'], rejected: ['proposed'], removed: ['auto', 'accepted'] };

interface TriageResult { line: Line; verdict?: IrTriageVerdict; error?: string; loading: boolean }

const IrEntities = ({ irId }: { irId: string }) => {
  const { t_i18n, nsdt } = useFormatter();
  const storageKey = `intelligenceRequirementEntities-${irId}`;
  const [preset, setPreset] = useState<Preset>('in');
  const [entityType, setEntityType] = useState<string | null>(null);
  const [countsKey, setCountsKey] = useState(0);
  const [selected, setSelected] = useState<Line | null>(null);
  const [triage, setTriage] = useState<Record<string, TriageResult> | null>(null);
  const requirement = useLazyLoadQuery<IrEntitiesRequirementQuery>(requirementQuery, { id: irId }).intelligenceRequirement;
  const criteria = requirement?.ir_scope_criteria ?? [];
  const kiqs = requirement?.ir_kiqs ?? [];
  const triageAgent = useIrTriageAgent();
  const [commitBulk, bulkInFlight] = useApiMutation<IrEntitiesBulkStatusMutation>(bulkStatusMutation);
  const { selectedElements, numberOfSelectedElements, handleClearSelectedElements } = useEntityToggle<Line & { id: string }>(storageKey);

  const initialValues = { searchTerm: '', sortBy: 'match_score', orderAsc: false, openExports: false, filters: emptyFilterGroup };
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<IrEntitiesLinesQuery$variables>(storageKey, initialValues);
  const contextFilters = useBuildEntityTypeBasedFilterContext(ENTITY_TYPE, viewStorage.filters);
  const presetDef = PRESETS.find((p) => p.value === preset) ?? PRESETS[0];
  // The status preset and the quick type filter are applied on top of the filters of the table
  const presetFilters = [
    ...(presetDef.excluded === undefined ? [] : [{ key: ['match_excluded'], values: [String(presetDef.excluded)], operator: 'eq', mode: 'or' }]),
    ...(entityType ? [{ key: ['match_entity_type'], values: [entityType], operator: 'eq', mode: 'or' }] : []),
  ];
  const queryFilters: FilterGroup = presetFilters.length === 0 ? contextFilters as FilterGroup : {
    mode: 'and',
    filters: presetFilters,
    filterGroups: [contextFilters as FilterGroup],
  } as FilterGroup;
  const queryPaginationOptions = { ...paginationOptions, id: irId, statuses: presetDef.statuses, filters: queryFilters } as unknown as IrEntitiesLinesQuery$variables;
  const [queryRef, loadQuery] = useQueryLoadingWithLoadQuery<IrEntitiesLinesQuery>(irEntitiesLinesQuery, queryPaginationOptions);
  const refresh = () => {
    loadQuery(queryPaginationOptions, { fetchPolicy: 'network-only' });
    setCountsKey((k) => k + 1);
  };

  const selection = Object.values(selectedElements);
  const applicable = (decision: Decision) => selection.filter((l) => DECISION_FROM[decision].includes(l.match_status));
  const decide = (decision: Decision, lines: Line[] = applicable(decision)) => {
    if (lines.length === 0) return;
    const onCompleted = () => {
      handleClearSelectedElements();
      refresh();
    };
    commitBulk({ variables: { ids: lines.map((l) => l.id), status: decision }, onCompleted });
  };

  const assessSelection = async () => {
    if (!triageAgent) return;
    const lines = selection.slice(0, MAX_BULK_TRIAGE);
    const state: Record<string, TriageResult> = Object.fromEntries(lines.map((l) => [l.id, { line: l, loading: true }]));
    setTriage({ ...state });
    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i];
      try {
        state[line.id] = { line, loading: false, verdict: await runTriage(triageAgent, irId, line.match_entity_id) };
      } catch (e) {
        state[line.id] = { line, loading: false, error: (e as Error).message };
      }
      setTriage({ ...state });
    }
  };
  const toReject = Object.values(triage ?? {}).filter((r) => r.verdict?.verdict === 'reject' && DECISION_FROM.rejected.includes(r.line.match_status));
  const toRemove = Object.values(triage ?? {}).filter((r) => r.verdict?.verdict === 'reject' && DECISION_FROM.removed.includes(r.line.match_status));

  const dataColumns: DataTableProps['dataColumns'] = {
    match_entity_name: {
      id: 'match_entity_name',
      label: 'Entity',
      percentWidth: 20,
      isSortable: true,
      render: (line: Line) => (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, minWidth: 0 }}>
          <Text as="span" variant="content-compact-medium" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {line.match_entity_name ?? line.entity?.representative.main ?? line.match_entity_id}
          </Text>
          <Text as="span" variant="content-caption" style={{ opacity: 0.6, whiteSpace: 'nowrap' }}>{t_i18n(`entity_${line.match_entity_type}`)}</Text>
        </Box>
      ),
    },
    match_status: { id: 'match_status', label: 'Status', percentWidth: 8, isSortable: true, render: (line: Line) => <StatusChip status={line.match_status} excluded={line.match_excluded} t={t_i18n} /> },
    match_score: { id: 'match_score', label: 'Score', percentWidth: 10, isSortable: true, render: (line: Line) => <ScoreBar score={line.match_score} excluded={line.match_excluded} /> },
    why: {
      id: 'why',
      label: 'Why it is in the requirement',
      percentWidth: 24,
      isSortable: false,
      render: (line: Line) => {
        const proof = line.match_explanations[0];
        if (!proof) return '-';
        return (
          <Text as="span" variant="content-caption" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {`${criterionName(criteria, proof.criterion_id)} · ${explanationText(proof)}${line.match_explanations.length > 1 ? ` (+${line.match_explanations.length - 1})` : ''}`}
          </Text>
        );
      },
    },
    reasons: {
      id: 'reasons',
      label: 'Score reasons',
      percentWidth: 16,
      isSortable: false,
      render: (line: Line) => (
        <Box sx={{ display: 'flex', gap: 0.5, overflow: 'hidden' }}>
          {line.match_score_breakdown.filter((o) => o.kind !== 'condition' && o.hit && o.points !== 0).slice(0, 2).map((o) => (
            <Box key={o.name} component="span" sx={{ fontSize: 11, border: '1px solid', borderColor: 'divider', borderRadius: 0.5, px: 0.75, whiteSpace: 'nowrap' }}>{`${o.name} ${o.points > 0 ? '+' : ''}${o.points}`}</Box>
          ))}
        </Box>
      ),
    },
    kiqs: {
      id: 'kiqs',
      label: 'KIQ',
      percentWidth: 6,
      isSortable: false,
      render: (line: Line) => <Text as="span" variant="content-caption">{String(kiqs.filter((k) => k.criteria_ids.some((c) => line.match_criteria_ids.includes(c))).length)}</Text>,
    },
    match_last_fact_at: { id: 'match_last_fact_at', label: 'Last fact', percentWidth: 8, isSortable: true, render: (line: Line) => <Text as="span" variant="content-caption">{line.match_last_fact_at ? nsdt(line.match_last_fact_at) : '-'}</Text> },
    created_at: { id: 'created_at', label: 'Entered', percentWidth: 8, isSortable: true, render: (line: Line) => <Text as="span" variant="content-caption">{nsdt(line.created_at)}</Text> },
  };

  return (
    <>
      {/* Status presets on the left, quick type filters on the right */}
      <Box sx={{ display: 'flex', gap: 3, mb: 1.5, alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <Box sx={{ display: 'flex', gap: 1, flexShrink: 0 }}>
          {PRESETS.map((p) => (
            <Button
              key={p.value}
              size="small"
              variant={preset === p.value ? 'primary' : 'secondary'}
              onClick={() => {
                setPreset(p.value);
                handleClearSelectedElements();
              }}
            >
              {t_i18n(p.label)}
            </Button>
          ))}
        </Box>
        <Suspense fallback={<Box sx={{ height: 32 }} />}>
          <TypeFilters
            irId={irId}
            statuses={presetDef.statuses}
            excluded={presetDef.excluded}
            value={entityType}
            fetchKey={countsKey}
            onChange={(type) => {
              setEntityType(type);
              handleClearSelectedElements();
            }}
          />
        </Suspense>
      </Box>
      {numberOfSelectedElements > 0 && (
        <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap', mb: 1, px: 1.5, py: 1, border: '1px solid', borderColor: 'divider', borderRadius: 1 }}>
          <Text as="span" variant="content-compact-bold">{`${numberOfSelectedElements} ${t_i18n('selected')}`}</Text>
          <Box sx={{ flex: 1 }} />
          {triageAgent && (
            <Button size="small" variant="secondary" intent="ai" onClick={assessSelection}>
              {`${t_i18n('Why is this of interest?')}${selection.length > MAX_BULK_TRIAGE ? ` (${MAX_BULK_TRIAGE} ${t_i18n('first')})` : ''}`}
            </Button>
          )}
          <Button size="small" disabled={bulkInFlight || applicable('accepted').length === 0} onClick={() => decide('accepted')}>{`${t_i18n('Accept')} (${applicable('accepted').length})`}</Button>
          <Button size="small" variant="secondary" disabled={bulkInFlight || applicable('rejected').length === 0} onClick={() => decide('rejected')}>{`${t_i18n('Reject')} (${applicable('rejected').length})`}</Button>
          <Button size="small" variant="secondary" disabled={bulkInFlight || applicable('removed').length === 0} onClick={() => decide('removed')}>{`${t_i18n('Remove from the requirement')} (${applicable('removed').length})`}</Button>
          <Button size="small" variant="tertiary" onClick={handleClearSelectedElements}>{t_i18n('Clear selection')}</Button>
        </Box>
      )}
      {queryRef && (
        <DataTable
          disableToolBar
          removeSelectAll
          dataColumns={dataColumns}
          resolvePath={(data: IrEntities_data$data) => data.intelligenceRequirementMatches?.edges?.map((e) => e?.node)}
          storageKey={storageKey}
          initialValues={initialValues}
          contextFilters={contextFilters}
          preloadedPaginationProps={{
            linesQuery: irEntitiesLinesQuery,
            linesFragment: irEntitiesLinesFragment,
            queryRef,
            nodePath: ['intelligenceRequirementMatches', 'pageInfo', 'globalCount'],
            setNumberOfElements: helpers.handleSetNumberOfElements,
          }}
          lineFragment={irEntitiesLineFragment}
          entityTypes={[ENTITY_TYPE]}
          searchContextFinal={{ entityTypes: [ENTITY_TYPE] }}
          icon={(line: Line) => <ItemIcon type={line.match_entity_type} size="small" />}
          onLineClick={(line: Line) => setSelected(line)}
        />
      )}
      <IrMatchDrawer
        irId={irId}
        match={selected as unknown as IrMatchData | null}
        criteria={criteria}
        onClose={() => setSelected(null)}
        onChanged={refresh}
      />
      <Drawer open={!!triage} onClose={() => setTriage(null)} title={t_i18n('AI opinion on the selection')} size="large">
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          {(toReject.length > 0 || toRemove.length > 0) && (
            <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
              <Text as="span" variant="content-compact">{t_i18n('The analyst decides. Apply the AI opinion to the entities rated "to reject":')}</Text>
              {toReject.length > 0 && <Button size="small" variant="secondary" onClick={() => decide('rejected', toReject.map((r) => r.line))}>{`${t_i18n('Reject')} (${toReject.length})`}</Button>}
              {toRemove.length > 0 && <Button size="small" variant="secondary" onClick={() => decide('removed', toRemove.map((r) => r.line))}>{`${t_i18n('Remove from the requirement')} (${toRemove.length})`}</Button>}
            </Box>
          )}
          {Object.values(triage ?? {}).map((result) => (
            <Box key={result.line.id} sx={{ display: 'flex', flexDirection: 'column', gap: 0.75 }}>
              <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                <ItemIcon type={result.line.match_entity_type} size="small" />
                <Text as="span" variant="content-compact-bold">{result.line.match_entity_name ?? result.line.match_entity_id}</Text>
                <StatusChip status={result.line.match_status} excluded={result.line.match_excluded} t={t_i18n} />
                {result.verdict && <Chip label={t_i18n(VERDICT_CHIPS[result.verdict.verdict].label)} severity={VERDICT_CHIPS[result.verdict.verdict].severity} />}
              </Box>
              <IrTriageCard verdict={result.verdict ?? null} loading={result.loading} error={result.error ?? null} />
            </Box>
          ))}
        </Box>
      </Drawer>
    </>
  );
};

export default IrEntities;
