import { graphql } from 'react-relay';
import { useSearchParams } from 'react-router';
import Box from '@mui/material/Box';
import Tag from '@common/tag/Tag';
import DataTable from '../../../../components/dataGrid/DataTable';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import { emptyFilterGroup, isFilterGroupNotEmpty, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { useQueryLoadingWithLoadQuery } from '../../../../utils/hooks/useQueryLoading';
import MergeRecordDrawer from './MergeRecordDrawer';
import useCurationLabels from './curationUtils';
import { MergeRecordsListQuery, MergeRecordsListQuery$variables } from './__generated__/MergeRecordsListQuery.graphql';
import { MergeRecords_records$data } from './__generated__/MergeRecords_records.graphql';
import { MergeRecords_record$data } from './__generated__/MergeRecords_record.graphql';

const mergeRecordFragment = graphql`
  fragment MergeRecords_record on MergeRecord {
    id
    entity_type
    name
    merge_target_id
    merge_target_type
    merge_target_name
    merge_source_names
    merge_status
    reversible_until
    is_reversible
    relationships_redirected_count
    created_at
    mergedBy {
      id
      name
    }
  }
`;

const mergeRecordsFragment = graphql`
  fragment MergeRecords_records on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "MergeRecordOrdering", defaultValue: created_at }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "MergeRecordsRefetchQuery") {
    mergeRecords(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_mergeRecords") {
      edges {
        node {
          id
          ...MergeRecords_record
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

const mergeRecordsListQuery = graphql`
  query MergeRecordsListQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: MergeRecordOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...MergeRecords_records
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

const LOCAL_STORAGE_KEY = 'curation_merge_records';
const ENTITY_LOCAL_STORAGE_KEY = 'curation_entity_merge_records';

interface MergeRecordsProps {
  /** Only the merges this entity took part in, as the surviving entity or as a merged one (the Merges view of its Changes tab). */
  entityId?: string;
}

const MergeRecords = ({ entityId }: MergeRecordsProps) => {
  const { t_i18n, fldt, n } = useFormatter();
  const labels = useCurationLabels();
  const { setTitle } = useConnectedDocumentModifier();
  if (!entityId) setTitle(t_i18n('Merges | Curation | Data'));
  const storageKey = entityId ? ENTITY_LOCAL_STORAGE_KEY : LOCAL_STORAGE_KEY;
  const [searchParams, setSearchParams] = useSearchParams();
  const recordId = searchParams.get('record');

  const initialValues = {
    searchTerm: '',
    sortBy: 'created_at',
    orderAsc: false,
    openExports: false,
    filters: emptyFilterGroup,
  };
  // In the Changes tab, the URL selects the section (`?section=merges`): the list keeps its state in local storage
  // only, as writing its parameters into the URL would replace the section parameter.
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<MergeRecordsListQuery$variables>(
    storageKey,
    initialValues,
    Boolean(entityId),
  );
  const typeContextFilters = useBuildEntityTypeBasedFilterContext('MergeRecord', viewStorage.filters);
  const contextFilters: FilterGroup = entityId ? {
    ...typeContextFilters,
    filterGroups: [...typeContextFilters.filterGroups, {
      mode: 'or',
      filters: [
        { key: 'merge_target_id', values: [entityId], operator: 'eq', mode: 'or' },
        { key: 'merge_source_ids', values: [entityId], operator: 'eq', mode: 'or' },
      ],
      filterGroups: [],
    }],
  } : typeContextFilters;
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as MergeRecordsListQuery$variables;
  const [queryRef, loadQuery] = useQueryLoadingWithLoadQuery<MergeRecordsListQuery>(mergeRecordsListQuery, queryPaginationOptions);

  const openRecord = (id: string | null) => {
    const next = new URLSearchParams(searchParams);
    if (id) next.set('record', id);
    else next.delete('record');
    setSearchParams(next);
  };

  const dataColumns: DataTableProps['dataColumns'] = {
    merge_target_name: {
      id: 'merge_target_name',
      label: 'Merged entity',
      percentWidth: 22,
      isSortable: true,
      render: ({ merge_target_name, merge_target_type }: MergeRecords_record$data) => (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, overflow: 'hidden' }}>
          <ItemIcon type={merge_target_type} size="small" />
          <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{merge_target_name}</span>
        </Box>
      ),
    },
    merge_source_names: {
      id: 'merge_source_names',
      label: 'Merged sources',
      percentWidth: 24,
      isSortable: false,
      render: ({ merge_source_names }: MergeRecords_record$data) => (
        <span title={merge_source_names.join(', ')}>{merge_source_names.join(', ')}</span>
      ),
    },
    merge_status: {
      id: 'merge_status',
      label: 'Status',
      percentWidth: 12,
      isSortable: true,
      render: ({ merge_status, reversible_until }: MergeRecords_record$data) => (
        <Tag label={labels.mergeStatus(merge_status, reversible_until)} color={labels.statusColor(merge_status)} />
      ),
    },
    merged_by: {
      id: 'merged_by',
      label: 'Merged by',
      percentWidth: 12,
      isSortable: false,
      render: ({ mergedBy }: MergeRecords_record$data) => mergedBy?.name ?? '-',
    },
    relationships_redirected_count: {
      id: 'relationships_redirected_count',
      label: 'Relationships redirected',
      percentWidth: 10,
      isSortable: false,
      render: ({ relationships_redirected_count }: MergeRecords_record$data) => n(relationships_redirected_count),
    },
    reversible_until: {
      id: 'reversible_until',
      label: 'Reversible until',
      percentWidth: 10,
      isSortable: true,
      render: ({ reversible_until, is_reversible }: MergeRecords_record$data) => (is_reversible ? fldt(reversible_until) : '-'),
    },
    created_at: {
      id: 'created_at',
      label: 'Merge date',
      percentWidth: 10,
      isSortable: true,
      render: ({ created_at }: MergeRecords_record$data) => fldt(created_at),
    },
  };

  return (
    <div data-testid={entityId ? 'entity-merge-records' : 'curation-merge-records-page'}>
      {queryRef && (
        <DataTable
          removeSelectAll
          disableLineSelection
          dataColumns={dataColumns}
          resolvePath={(data: MergeRecords_records$data) => data.mergeRecords?.edges?.map((edge) => edge?.node)}
          storageKey={storageKey}
          initialValues={initialValues}
          ignoreUri={Boolean(entityId)}
          contextFilters={contextFilters}
          emptyStateMessage={viewStorage.searchTerm || isFilterGroupNotEmpty(viewStorage.filters) ? undefined : (entityId
            ? t_i18n('This entity took part in no recorded merge.')
            : t_i18n('No merge recorded yet. Every merge, from Data > Entities, the API, the deduplication or a curation proposal, appears here and can be undone during its retention window.'))}
          preloadedPaginationProps={{
            linesQuery: mergeRecordsListQuery,
            linesFragment: mergeRecordsFragment,
            queryRef,
            nodePath: ['mergeRecords', 'pageInfo', 'globalCount'],
            setNumberOfElements: helpers.handleSetNumberOfElements,
          }}
          lineFragment={mergeRecordFragment}
          entityTypes={['MergeRecord']}
          searchContextFinal={{ entityTypes: ['MergeRecord'] }}
          onLineClick={(line: { id: string }) => openRecord(line.id)}
        />
      )}
      <MergeRecordDrawer
        recordId={recordId}
        onClose={() => openRecord(null)}
        onUnmerged={() => loadQuery(queryPaginationOptions, { fetchPolicy: 'network-only' })}
      />
    </div>
  );
};

export default MergeRecords;
