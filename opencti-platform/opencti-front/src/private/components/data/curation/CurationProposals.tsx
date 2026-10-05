import { Suspense, useState } from 'react';
import { graphql } from 'react-relay';
import Box from '@mui/material/Box';
import Tag from '@common/tag/Tag';
import DataTable from '../../../../components/dataGrid/DataTable';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { useQueryLoadingWithLoadQuery } from '../../../../utils/hooks/useQueryLoading';
import useGranted, { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import { Filter, FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import CurationConfidence from './CurationConfidence';
import CurationFirstUse from './CurationFirstUse';
import CurationProposalsToolBar from './CurationProposalsToolBar';
import CurationStatisticsBar, { CurationInboxFilter, CurationStatisticsBarSkeleton, hasNoProposalYet, useCurationStatistics } from './CurationStatisticsBar';
import useCurationLabels, { CURATION_PROPOSALS_PATH } from './curationUtils';
import { CurationProposalsListQuery, CurationProposalsListQuery$variables } from './__generated__/CurationProposalsListQuery.graphql';
import { CurationProposals_proposals$data } from './__generated__/CurationProposals_proposals.graphql';
import { CurationProposals_proposal$data } from './__generated__/CurationProposals_proposal.graphql';

const proposalFragment = graphql`
  fragment CurationProposals_proposal on CurationProposal {
    id
    entity_type
    name
    proposal_kind
    proposal_status
    confidence_score
    in_ambiguous_band
    detector
    subject_ids
    subject_types
    subject_names
    recommended_action
    choice_required
    can_apply
    created_at
    decided_at
  }
`;

const proposalsFragment = graphql`
  fragment CurationProposals_proposals on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "CurationProposalOrdering", defaultValue: confidence_score }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "CurationProposalsRefetchQuery") {
    curationProposals(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_curationProposals") {
      edges {
        node {
          id
          ...CurationProposals_proposal
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

export const curationProposalsListQuery = graphql`
  query CurationProposalsListQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: CurationProposalOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...CurationProposals_proposals
    @arguments(
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

const LOCAL_STORAGE_KEY = 'curation_proposals';

const OPEN_STATUS_FILTER: Filter = { key: 'proposal_status', values: ['open'], operator: 'eq', mode: 'or' };
const AMBIGUOUS_FILTER: Filter = { key: 'in_ambiguous_band', values: ['true'], operator: 'eq', mode: 'or' };

export const openProposalsFilter: FilterGroup = { mode: 'and', filters: [OPEN_STATUS_FILTER], filterGroups: [] };
const needsDecisionFilter: FilterGroup = { mode: 'and', filters: [OPEN_STATUS_FILTER, AMBIGUOUS_FILTER], filterGroups: [] };

const isFilterOf = (filter: Filter, expected: Filter) => {
  return filter.key === expected.key && (filter.operator ?? 'eq') === 'eq' && filter.values.length === 1 && filter.values[0] === expected.values[0];
};

/** The counter of the statistics strip that the current filters match, if any. */
const activeInboxFilter = (filters: FilterGroup | undefined): CurationInboxFilter | null => {
  const items = filters?.filters ?? [];
  if ((filters?.filterGroups ?? []).length > 0) return null;
  if (items.length === 1 && isFilterOf(items[0], OPEN_STATUS_FILTER)) return 'open';
  if (items.length === 2 && items.some((item) => isFilterOf(item, OPEN_STATUS_FILTER)) && items.some((item) => isFilterOf(item, AMBIGUOUS_FILTER))) {
    return 'needs_decision';
  }
  return null;
};

const CurationProposalsComponent = () => {
  const { t_i18n } = useFormatter();
  const labels = useCurationLabels();
  const isGrantedToUpdate = useGranted([KNOWLEDGE_KNUPDATE]);
  const [statisticsKey, setStatisticsKey] = useState(0);
  const statistics = useCurationStatistics(statisticsKey);

  const initialValues = {
    searchTerm: '',
    sortBy: 'confidence_score',
    orderAsc: false,
    openExports: false,
    filters: openProposalsFilter,
  };
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<CurationProposalsListQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  const contextFilters = useBuildEntityTypeBasedFilterContext('CurationProposal', viewStorage.filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as CurationProposalsListQuery$variables;
  const [queryRef, loadQuery] = useQueryLoadingWithLoadQuery<CurationProposalsListQuery>(curationProposalsListQuery, queryPaginationOptions);
  const refresh = () => {
    loadQuery(queryPaginationOptions, { fetchPolicy: 'network-only' });
    setStatisticsKey((key) => key + 1);
  };
  const applyInboxFilter = (filter: CurationInboxFilter) => {
    helpers.handleSetFilters(filter === 'open' ? openProposalsFilter : needsDecisionFilter);
  };

  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      id: 'name',
      label: 'Proposal',
      percentWidth: 26,
      isSortable: true,
      render: ({ name, subject_types }: CurationProposals_proposal$data) => (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, overflow: 'hidden' }}>
          <ItemIcon type={subject_types[0] ?? 'Unknown'} size="small" />
          <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{name}</span>
        </Box>
      ),
    },
    proposal_kind: {
      id: 'proposal_kind',
      label: 'Kind',
      percentWidth: 13,
      isSortable: true,
      render: ({ proposal_kind }: CurationProposals_proposal$data) => <Tag label={labels.kind(proposal_kind)} />,
    },
    recommended_action: {
      id: 'recommended_action',
      label: 'Recommended action',
      percentWidth: 16,
      isSortable: false,
      render: ({ recommended_action }: CurationProposals_proposal$data) => labels.action(recommended_action),
    },
    confidence_score: {
      id: 'confidence_score',
      label: 'Confidence',
      percentWidth: 14,
      isSortable: true,
      render: ({ confidence_score, in_ambiguous_band }: CurationProposals_proposal$data) => (
        <CurationConfidence value={confidence_score} ambiguous={in_ambiguous_band} />
      ),
    },
    detector: {
      id: 'detector',
      label: 'Detector',
      percentWidth: 12,
      isSortable: false,
      render: ({ detector }: CurationProposals_proposal$data) => labels.detector(detector),
    },
    proposal_status: {
      id: 'proposal_status',
      label: 'Status',
      percentWidth: 9,
      isSortable: true,
      render: ({ proposal_status }: CurationProposals_proposal$data) => (
        <Tag label={labels.status(proposal_status)} color={labels.statusColor(proposal_status)} />
      ),
    },
    created_at: {
      id: 'created_at',
      percentWidth: 10,
    },
  };

  const statisticsBar = (
    <CurationStatisticsBar statistics={statistics} activeFilter={activeInboxFilter(viewStorage.filters)} onFilter={applyInboxFilter} />
  );
  if (hasNoProposalYet(statistics)) {
    return (
      <>
        {statisticsBar}
        <CurationFirstUse
          testId="curation-inbox-first-use"
          title={t_i18n('No curation proposal yet')}
          description={t_i18n('The curation manager scans your knowledge every night and lists here the duplicates, contradictions and stale knowledge it finds, each with its evidence and a recommended action.')}
          nextRunDate={statistics.next_scan_date}
        />
      </>
    );
  }
  return (
    <>
      {statisticsBar}
      {queryRef && (
        <DataTable
          removeSelectAll
          disableLineSelection={!isGrantedToUpdate}
          dataColumns={dataColumns}
          resolvePath={(data: CurationProposals_proposals$data) => data.curationProposals?.edges?.map((edge) => edge?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          contextFilters={contextFilters}
          preloadedPaginationProps={{
            linesQuery: curationProposalsListQuery,
            linesFragment: proposalsFragment,
            queryRef,
            nodePath: ['curationProposals', 'pageInfo', 'globalCount'],
            setNumberOfElements: helpers.handleSetNumberOfElements,
          }}
          lineFragment={proposalFragment}
          entityTypes={['CurationProposal']}
          searchContextFinal={{ entityTypes: ['CurationProposal'] }}
          getComputeLink={(node: { id: string }) => `${CURATION_PROPOSALS_PATH}/${node.id}`}
          customToolbar={<CurationProposalsToolBar onDone={refresh} />}
        />
      )}
    </>
  );
};

const CurationProposals = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Inbox | Curation | Data'));
  return (
    <div data-testid="curation-proposals-page">
      <Suspense fallback={<CurationStatisticsBarSkeleton />}>
        <CurationProposalsComponent />
      </Suspense>
    </div>
  );
};

export default CurationProposals;
