import { getDraftModeColor } from '@components/common/draft/DraftChip';
import DraftWorkspaceDialogCreation from '@components/common/files/draftWorkspace/DraftWorkspaceDialogCreation';
import ImportMenu from '@components/data/ImportMenu';
import DraftCreation from '@components/drafts/DraftCreation';
import Chip from '@mui/material/Chip';
import { useTheme } from '@mui/styles';
import { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import Breadcrumbs from '../../../components/Breadcrumbs';
import DataTable from '../../../components/dataGrid/DataTable';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import { defaultRender } from '../../../components/dataGrid/dataTableUtils';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import { hexToRGB } from '../../../utils/Colors';
import { computeValidationProgress } from '../../../utils/draft/draftUtils';
import { addFilter, emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { DraftsLines_data$data } from './__generated__/DraftsLines_data.graphql';
import { DraftsLinesPaginationQuery, DraftsLinesPaginationQuery$variables } from './__generated__/DraftsLinesPaginationQuery.graphql';
import DraftPopover from './DraftPopover';

const DraftLineFragment = graphql`
    fragment Drafts_node on DraftWorkspace {
        id
        entity_type
        name
        creators {
          id
          name
        }
        created_at
        draft_status
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
export const draftsLinesQuery = graphql`
    query DraftsLinesPaginationQuery(
        $search: String
        $count: Int!
        $cursor: ID
        $orderBy: DraftWorkspacesOrdering
        $orderMode: OrderingMode
        $filters: FilterGroup
    ) {
        ...DraftsLines_data
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

export const draftsLinesFragment = graphql`
    fragment DraftsLines_data on Query
    @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "DraftWorkspacesOrdering", defaultValue: created_at }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "FilterGroup" }
    )
    @refetchable(queryName: "DraftsLinesRefetchQuery") {
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
                    ...Drafts_node
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

const LOCAL_STORAGE_KEY = 'draftWorkspaces';

interface DraftsProps {
  entityId?: string;
  openCreate?: boolean;
  setOpenCreate?: () => void;
  emptyStateMessage?: string
}

const Drafts: FunctionComponent<DraftsProps> = ({ entityId, openCreate, setOpenCreate, emptyStateMessage }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const draftColor = getDraftModeColor(theme);
  const validatedDraftColor = theme.palette.success.main;
  const draftContext = useDraftContext();
  const { setTitle } = useConnectedDocumentModifier();
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
  } = usePaginationLocalStorage<DraftsLinesPaginationQuery$variables>(LOCAL_STORAGE_KEY, initialValues);
  const {
    filters,
  } = viewStorage;

  const filtersForDataTable = addFilter(filters, 'entity_id', [entityId || ''], entityId ? 'eq' : 'nil', 'and');
  const contextFilters = useBuildEntityTypeBasedFilterContext('DraftWorkspace', filtersForDataTable);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as DraftsLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<DraftsLinesPaginationQuery>(
    draftsLinesQuery,
    queryPaginationOptions,
  );

  const preloadedPaginationProps = {
    linesQuery: draftsLinesQuery,
    linesFragment: draftsLinesFragment,
    queryRef,
    nodePath: ['draftWorkspaces', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<DraftsLinesPaginationQuery>;

  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      percentWidth: 50,
      isSortable: true,
    },
    creator: {
      percentWidth: 15,
      isSortable: true,
    },
    created_at: {
      percentWidth: 15,
      isSortable: true,
    },
    draft_status: {
      id: 'draft_status',
      label: 'Status',
      percentWidth: 10,
      isSortable: true,
      render: ({ draft_status }) => (
        <Chip
          variant="outlined"
          label={draft_status}
          style={{
            fontSize: 12,
            lineHeight: '12px',
            height: 20,
            float: 'left',
            textTransform: 'uppercase',
            borderRadius: 4,
            width: 90,
            color: draft_status === 'open' ? draftColor : validatedDraftColor,
            borderColor: draft_status === 'open' ? draftColor : validatedDraftColor,
            backgroundColor: hexToRGB(draft_status === 'open' ? draftColor : validatedDraftColor),
          }}
        />
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

  return (
    <span data-testid="draft-page">
      {!entityId && (
        <>
          <Breadcrumbs
            elements={[{ label: t_i18n('Data') }, { label: t_i18n('Import'), current: true }]}
          />
          <ImportMenu />
        </>
      )}
      {queryRef && (
        <>
          <DataTable
            dataColumns={dataColumns}
            resolvePath={(data: DraftsLines_data$data) => (data.draftWorkspaces?.edges ?? []).map((n) => n?.node)}
            storageKey={LOCAL_STORAGE_KEY}
            initialValues={initialValues}
            toolbarFilters={contextFilters}
            preloadedPaginationProps={preloadedPaginationProps}
            lineFragment={DraftLineFragment}
            hideSearch={!!entityId}
            hideFilters={!!entityId}
            hideHeaders={!!entityId}
            disableLineSelection={!!entityId}
            emptyStateMessage={emptyStateMessage}
            createButton={!draftContext && <DraftCreation paginationOptions={queryPaginationOptions} />}
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
