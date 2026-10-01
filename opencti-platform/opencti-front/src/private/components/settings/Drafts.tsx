import { useState, useMemo } from 'react';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { FunctionComponent } from 'react';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { useFormatter } from '../../../components/i18n';
import { defaultRender } from '../../../components/dataGrid/dataTableUtils';
import { useTheme } from '@mui/styles';
import { Theme } from '@mui/material/styles/createTheme';
import DraftStatusChip from '@components/common/draft/DraftStatusChip';
import DraftWorkspaceDialogCreation from '@components/common/files/draftWorkspace/DraftWorkspaceDialogCreation';
import { computeValidationProgress } from '../../../utils/draft/draftUtils';
import { addFilter, emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import Breadcrumbs from '../../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import DataTable from '../../../components/dataGrid/DataTable';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { DraftsLinesSettings_data$data } from './__generated__/DraftsLinesSettings_data.graphql';
import { DraftsLinesPaginationSettingsQuery, DraftsLinesPaginationSettingsQuery$variables } from './__generated__/DraftsLinesPaginationSettingsQuery.graphql';
import DraftPopover from '../drafts/DraftPopover';
import useRuntimeSortGuard from '../../../utils/hooks/useRuntimeSortGuard';
import ItemStatus from 'src/components/ItemStatus';
import type { DraftRetentionQuery$data } from './__generated__/DraftRetentionQuery.graphql';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import useAuth from '../../../utils/hooks/useAuth';

const DraftLineSettingsFragment = graphql`
    fragment Drafts_settings_node on DraftWorkspace {
        id
        entity_type
        name
      description
      createdBy {
        ... on Identity {
          id
          name
          entity_type
        }
      }
        creators {
          id
          name
        }
        created_at
      objectAssignee {
        id
        name
        entity_type
      }
      objectParticipant {
        id
        name
        entity_type
      }
        draft_status
        workflowInstance {
          id
          currentStatus {
            id
            template {
              name
              color
            }
          }
        }
        validationWork {
            received_time
            processed_time
            completed_time
            tracking {
                import_expected_number
                import_processed_number
            }
        }
        currentUserAccessRight
        authorizedMembers {
          id
          name
          entity_type
          access_right
          member_id
          groups_restriction {
            id
            name
          }
        }
      }
`;
export const draftsLinesSettingsQuery = graphql`
    query DraftsLinesPaginationSettingsQuery(
        $search: String
        $count: Int!
        $cursor: ID
        $orderBy: DraftWorkspacesOrdering
        $orderMode: OrderingMode
        $filters: FilterGroup
    ) {
        ...DraftsLinesSettings_data
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

export const draftsLinesSettingsFragment = graphql`
    fragment DraftsLinesSettings_data on Query
    @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "DraftWorkspacesOrdering", defaultValue: created_at }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "FilterGroup" }
    )
    @refetchable(queryName: "DraftsLinesRefetchSettingsQuery") {
        draftWorkspaces(
            search: $search
            first: $count
            after: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
            filters: $filters
        ) @connection(key: "Pagination_draftWorkspaces") {
            edges {
                node {
                    id
                    created_at
                    ...Drafts_settings_node
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

const DraftRetentionQuery = graphql`
  query DraftRetentionQuery {
    retentionRules(
      filters: {
        mode: and
        filters: [{ key: "scope", values: ["draft"] }, { key: "active", values: true }]
        filterGroups: []
      }
    ) {
      edges {
        node {
          max_retention
          retention_unit
        }
      }
    }
  }
`;

const LOCAL_STORAGE_KEY = 'draftWorkspaces';

interface DraftsProps {
  entityId?: string;
  openCreate?: boolean;
  setOpenCreate?: () => void;
  emptyStateMessage?: string;
}

const Drafts: FunctionComponent<DraftsProps> = ({ entityId, openCreate, setOpenCreate, emptyStateMessage }) => {
  const { platformModuleHelpers: { isRuntimeFieldEnable } } = useAuth();
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  const theme = useTheme<Theme>();
  if (!entityId) {
    setTitle(t_i18n('Drafts'));
  }

  const initialValues = {
    filters: emptyFilterGroup,
    searchTerm: '',
    sortBy: 'created_at',
    orderAsc: false,
    openExports: false,
    redirectionMode: 'overview',
  };
  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<DraftsLinesPaginationSettingsQuery$variables>(LOCAL_STORAGE_KEY, initialValues);
  const {
    filters,
  } = viewStorage;

  // Compute safeSortBy synchronously to prevent the initial Relay query from using an
  // unsupported orderBy (runtime-only field on OpenSearch) before the effect repairs state.
  const safeSortBy = useRuntimeSortGuard(isRuntimeSort, viewStorage.sortBy, storageHelpers.handleSort);

  const filtersForDataTable = addFilter(filters, 'entity_id', [entityId || ''], entityId ? 'eq' : 'nil', 'and');
  const contextFilters = useBuildEntityTypeBasedFilterContext('DraftWorkspace', filtersForDataTable);
  const queryPaginationOptions = {
    ...paginationOptions,
    orderBy: safeSortBy,
    filters: contextFilters,
  } as unknown as DraftsLinesPaginationSettingsQuery$variables;
  const queryRef = useQueryLoading<DraftsLinesPaginationSettingsQuery>(
    draftsLinesSettingsQuery,
    queryPaginationOptions,
  );

  const preloadedPaginationProps = {
    linesQuery: draftsLinesSettingsQuery,
    linesFragment: draftsLinesSettingsFragment,
    queryRef,
    nodePath: ['draftWorkspaces', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<DraftsLinesPaginationSettingsQuery>;

  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      percentWidth: 28,
      isSortable: true,
    },
    creator: {
      percentWidth: 10,
      isSortable: true,
    },
    created_at: {
      percentWidth: 12,
      isSortable: true,
    },
    modified: {
      percentWidth: 12,
      isSortable: true,
    },
    createdBy: {
      percentWidth: 10,
      isSortable: isRuntimeSort,
    },
    objectAssignee: {
      percentWidth: 10,
      isSortable: isRuntimeSort,
    },
    objectParticipant: {
      percentWidth: 10,
      isSortable: isRuntimeSort,
    },
    draft_status: {
      id: 'draft_status',
      label: 'Status',
      percentWidth: 10,
      isSortable: true,
      render: (node) => (
        node.workflowInstance?.currentStatus ? (
          <ItemStatus status={node.workflowInstance.currentStatus} />
        ) : (
          <DraftStatusChip draftStatus={node.draft_status} />
        )
      ),
    },
    draft_validation_progress: {
      id: 'draft_validation_progress',
      label: 'Validation progress',
      percentWidth: 10,
      isSortable: false,
      render: ({ validationWork }) => defaultRender(computeValidationProgress(validationWork)),
    },
  };
  const daysStale = Array.from({ length: 7 }, (value, i) => i === 0 ? 1 : i * 5);
  const [daysSelected, setDaysSelected] = useState('30');
  const [staleCount, setStaleCount] = useState(0);
  const draftRetentionData = useLazyLoadQuery(DraftRetentionQuery, {}) as DraftRetentionQuery$data;
  type RetentionNode = NonNullable<NonNullable<NonNullable<DraftRetentionQuery$data['retentionRules']>['edges']>[number]>['node'];
  const draftRetentionObj: RetentionNode | null = draftRetentionData?.retentionRules?.edges?.[0]?.node ?? null;
  type WorkspaceRowNode = NonNullable<NonNullable<NonNullable<DraftsLinesSettings_data$data['draftWorkspaces']>['edges']>[number]>['node'];
  const [tableRows, setTableRows] = useState<WorkspaceRowNode[]>([]);

  const findStaleCount = (selectorDaysSelected: string) => {
    if (draftRetentionObj && draftRetentionObj.retention_unit && draftRetentionObj.max_retention) {
      const now = new Date().getTime();
      const msPerDay = 24 * 60 * 60 * 1000;
      let tempStaleCount = 0;

      if (draftRetentionObj.retention_unit === 'days' || draftRetentionObj.retention_unit === 'hours' || draftRetentionObj.retention_unit === 'minutes') {
        for (const row of tableRows as Record<string, unknown>[]) {
          const creationDate = new Date(row.created_at as string);
          const deletionTime = creationDate.getTime() + (draftRetentionObj.max_retention
            * (draftRetentionObj.retention_unit === 'days' ? msPerDay
              : (draftRetentionObj.retention_unit === 'hours' ? (60 * 60 * 1000)
                  : (draftRetentionObj.retention_unit === 'minutes' ? (60 * 1000) : (0)))));
          const daysUntilDeletion = (deletionTime - now) / msPerDay;

          if (daysUntilDeletion >= 0 && daysUntilDeletion <= parseInt(selectorDaysSelected))
            tempStaleCount++;
        }
      }
      setStaleCount(tempStaleCount);
    }
  };

  useMemo(() => {
    findStaleCount(daysSelected);
  }, [tableRows]);

  return (
    <span data-testid="draft-page" style={{ display: 'block', width: 'calc(100% - 184px)' }}>
      {!entityId && (
        <>
          <Breadcrumbs elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Management') }, { label: t_i18n('Drafts'), current: true }]} />
        </>
      )}
      {queryRef && (
        <>
          <div style={{ padding: '8px 0' }}>
            <span style={{ color: theme.palette.primary.main }}>{staleCount} stale drafts</span>&nbsp;<span>found within</span>
            <select
              id="daysStale"
              style={{ margin: '0 4px' }}
              value={daysSelected}
              onChange={(e) => {
                setDaysSelected(e.target.value);
                findStaleCount(e.target.value);
              }}
            >
              {daysStale.map((dayCount) => (
                <option key={dayCount} value={dayCount}>
                  {dayCount}
                </option>
              ))}
            </select>
            <span>days of </span> <span style={{ color: theme.palette.primary.main }}>{draftRetentionObj ? draftRetentionObj.max_retention : ''} {draftRetentionObj ? draftRetentionObj.retention_unit : ''}</span> <span>retention policy on this page of results</span>
          </div>
          <DataTable
            dataColumns={dataColumns}
            resolvePath={(data: DraftsLinesSettings_data$data) => {
              // Statement 1: Extract rows
              const rows = (data.draftWorkspaces?.edges ?? []).map((n) => n?.node);

              // Statement 2: Update state asynchronously
              setTimeout(() => setTableRows(rows), 0);

              // Statement 3: Return rows
              return rows;
            }}
            storageKey={LOCAL_STORAGE_KEY}
            initialValues={initialValues}
            entityTypes={['DraftWorkspace']}
            contextFilters={contextFilters}
            preloadedPaginationProps={preloadedPaginationProps}
            lineFragment={DraftLineSettingsFragment}
            hideSearch={!!entityId}
            hideFilters={!!entityId}
            hideHeaders={!!entityId}
            disableLineSelection={!!entityId}
            emptyStateMessage={emptyStateMessage}
            actions={(row) => (
              <DraftPopover
                draftId={row.id}
                draftLocked={row.draft_status !== 'open'}
                paginationOptions={queryPaginationOptions}
                currentUserAccessRight={row.currentUserAccessRight}
              />
            )}
          />
          {openCreate && (
            <DraftWorkspaceDialogCreation
              paginationOptions={queryPaginationOptions}
              handleCloseCreate={setOpenCreate}
              entityId={entityId}
              openCreate={openCreate}
            />
          )}
        </>
      )}
    </span>
  );
};

export default Drafts;
