import React, { FunctionComponent } from 'react';
import { DraftsLinesPaginationQuery, DraftsLinesPaginationQuery$variables } from '@components/drafts/__generated__/DraftsLinesPaginationQuery.graphql';
import DraftCreation from '@components/drafts/DraftCreation';
import { graphql } from 'react-relay';
import { DraftsLines_data$data } from '@components/drafts/__generated__/DraftsLines_data.graphql';
import { Drafts_node$data } from '@components/drafts/__generated__/Drafts_node.graphql';
import Chip from '@mui/material/Chip';
import { useTheme } from '@mui/styles';
import { getDraftModeColor } from '@components/common/draft/DraftChip';
import ImportMenu from '@components/data/ImportMenu';
import { DraftContextBannerMutation } from '@components/drafts/__generated__/DraftContextBannerMutation.graphql';
import { draftContextBannerMutation } from '@components/drafts/DraftContextBanner';
import { useNavigate } from 'react-router-dom';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { useFormatter } from '../../../components/i18n';
import {
  addFilter,
  emptyFilterGroup, isFilterGroupNotEmpty,
  useBuildEntityTypeBasedFilterContext, useGetDefaultFilterObject,
  useRemoveIdAndIncorrectKeysFromFilterGroupObject
} from '../../../utils/filters/filtersUtils';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import DataTable from '../../../components/dataGrid/DataTable';
import DraftPopover from './DraftPopover';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import { defaultRender } from '../../../components/dataGrid/dataTableUtils';
import { hexToRGB } from '../../../utils/Colors';
import type { Theme } from '../../../components/Theme';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import {FilterGroup} from "../../../utils/filters/filtersHelpers-types";

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

const computeValidationProgress = (validationWork: Drafts_node$data['validationWork']) => {
  if (!validationWork) {
    return '';
  }
  if (!validationWork.tracking?.import_expected_number || !validationWork.tracking?.import_processed_number) {
    return '0%';
  }

  return `${Math.floor(100 * (validationWork.tracking.import_processed_number / validationWork.tracking.import_expected_number))}%`;
};

interface DraftProps {
  entityId?: string;
}

const Drafts: FunctionComponent<DraftProps> = ({ entityId }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const draftColor = getDraftModeColor(theme);
  const navigate = useNavigate();
  const validatedDraftColor = theme.palette.success.main;
  const draftContext = useDraftContext();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Drafts'));
  const [commitSwitchToDraft] = useApiMutation<DraftContextBannerMutation>(draftContextBannerMutation);

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

  const handleDraftSelection = (id: string) => {
    commitSwitchToDraft({
      variables: {
        input: [{ key: 'draft_context', value: [id] }],
      },
      onCompleted: () => {
        navigate('/dashboard/data/import/draft');
      },
    });
  };

  const renderInEntity = () => {
    return (
      <>
        {queryRef && (
          <DataTable
            dataColumns={dataColumns}
            hideHeaders={true}
            storageKey={LOCAL_STORAGE_KEY}
            hideFilters={true}
            resolvePath={(data: DraftsLines_data$data) => (data.draftWorkspaces?.edges ?? []).map((n) => n?.node)}
            lineFragment={DraftLineFragment}
            hideSearch={true}
            onLineClick={(row) => handleDraftSelection(row.id)}
            disableLineSelection
            initialValues={initialValues}
            preloadedPaginationProps={preloadedPaginationProps}
            actions={(row) => (
              <DraftPopover
                draftId={row.id}
                draftLocked={row.draft_status !== 'open'}
                paginationOptions={queryPaginationOptions}
              />
            )}
          />
        )}
      </>
    );
  };

  return (
    <span data-testid="draft-page">
      {entityId ? (
        renderInEntity()
      ) : (
        <>
          <Breadcrumbs
            elements={[{ label: t_i18n('Data') }, { label: t_i18n('Import'), current: true }]}
          />
          <ImportMenu />
          {queryRef && (
            <DataTable
              dataColumns={dataColumns}
              resolvePath={(data: DraftsLines_data$data) => (data.draftWorkspaces?.edges ?? []).map((n) => n?.node)
              }
              storageKey={LOCAL_STORAGE_KEY}
              initialValues={initialValues}
              toolbarFilters={contextFilters}
              preloadedPaginationProps={preloadedPaginationProps}
              lineFragment={DraftLineFragment}
              createButton={
                !draftContext && <DraftCreation paginationOptions={queryPaginationOptions} />
              }
              actions={(row) => (
                <DraftPopover
                  draftId={row.id}
                  draftLocked={row.draft_status !== 'open'}
                  paginationOptions={queryPaginationOptions}
                />
              )}
            />
          )}
        </>
      )}
    </span>
  );
};

export default Drafts;
