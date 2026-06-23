import { getDraftModeColor } from '@components/common/draft/DraftChip';
import { DraftsLinesPaginationQuery, DraftsLinesPaginationQuery$variables } from '@components/drafts/__generated__/DraftsLinesPaginationQuery.graphql';
import Chip from '@mui/material/Chip';
import { useTheme } from '@mui/styles';
import { useState } from 'react';
import { graphql } from 'react-relay';
import Alert from '../../../../components/Alert';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import DataTable from '../../../../components/dataGrid/DataTable';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import { defaultRender } from '../../../../components/dataGrid/dataTableUtils';
import { useFormatter } from '../../../../components/i18n';
import ItemStatus from '../../../../components/ItemStatus';
import type { Theme } from '../../../../components/Theme';
import { hexToRGB } from '../../../../utils/Colors';
import { computeValidationProgress } from '../../../../utils/draft/draftUtils';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import useAuth from '../../../../utils/hooks/useAuth';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import useHelper from '../../../../utils/hooks/useHelper';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useRuntimeSortGuard from '../../../../utils/hooks/useRuntimeSortGuard';
import { RestrictedDrafts_node$data } from './__generated__/RestrictedDrafts_node.graphql';
import { RestrictedDraftsLines_data$data } from './__generated__/RestrictedDraftsLines_data.graphql';

export const RestrictedDraftLineFragment = graphql`
    fragment RestrictedDrafts_node on DraftWorkspace {
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

const restrictedDraftsLinesQuery = graphql`
    query RestrictedDraftsLinesPaginationQuery(
        $search: String
        $count: Int!
        $cursor: ID
        $orderBy: DraftWorkspacesOrdering
        $orderMode: OrderingMode
        $filters: FilterGroup
    ) {
        ...RestrictedDraftsLines_data
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

const restrictedDraftsLinesFragment = graphql`
    fragment RestrictedDraftsLines_data on Query
    @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "DraftWorkspacesOrdering", defaultValue: created_at }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "FilterGroup" }
    )
    @refetchable(queryName: "RestrictedDraftsLinesRefetchQuery") {
        draftWorkspacesRestricted(
            search: $search
            first: $count
            after: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
            filters: $filters
        ) @connection(key: "Pagination_draftWorkspacesRestricted") {
            edges {
                node {
                    id
                    ...RestrictedDrafts_node
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

const LOCAL_STORAGE_KEY = 'draftWorkspacesRestricted';

const RestrictedDrafts = () => {
  const [ref, setRef] = useState<HTMLDivElement | undefined>(undefined);
  const { isFeatureEnable } = useHelper();
  const { platformModuleHelpers: { isRuntimeFieldEnable } } = useAuth();
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const draftColor = getDraftModeColor(theme);
  const validatedDraftColor = theme.palette.success.main;

  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Restricted Drafts | Restriction | Data'));

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

  useRuntimeSortGuard(isRuntimeSort, viewStorage.sortBy, storageHelpers.handleSort);

  const contextFilters = useBuildEntityTypeBasedFilterContext('DraftWorkspace', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as DraftsLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<DraftsLinesPaginationQuery>(
    restrictedDraftsLinesQuery,
    queryPaginationOptions,
  );

  const preloadedPaginationProps = {
    linesQuery: restrictedDraftsLinesQuery,
    linesFragment: restrictedDraftsLinesFragment,
    queryRef,
    nodePath: ['draftWorkspacesRestricted', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<DraftsLinesPaginationQuery>;

  const dataColumnsWithoutMetadata: DataTableProps['dataColumns'] = {
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
      render: ({ draft_status }: RestrictedDrafts_node$data) => (
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
      render: ({ validationWork }: RestrictedDrafts_node$data) => defaultRender(computeValidationProgress<RestrictedDrafts_node$data['validationWork']>(validationWork)),
    },
  };

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
      render: (node: RestrictedDrafts_node$data) => (
        node.workflowInstance?.currentStatus ? (
          <ItemStatus status={node.workflowInstance.currentStatus} />
        ) : (
          <Chip
            variant="outlined"
            label={node.draft_status}
            style={{
              fontSize: 12,
              lineHeight: '12px',
              height: 20,
              float: 'left',
              textTransform: 'uppercase',
              borderRadius: 4,
              width: 90,
              color: node.draft_status === 'open' ? draftColor : validatedDraftColor,
              borderColor: node.draft_status === 'open' ? draftColor : validatedDraftColor,
              backgroundColor: hexToRGB(node.draft_status === 'open' ? draftColor : validatedDraftColor),
            }}
          />
        )
      ),
    },
    draft_validation_progress: {
      id: 'draft_validation_progress',
      label: 'Validation progress',
      percentWidth: 10,
      isSortable: false,
      render: ({ validationWork }: RestrictedDrafts_node$data) => defaultRender(computeValidationProgress<RestrictedDrafts_node$data['validationWork']>(validationWork)),
    },
  };

  return (
    <>
      <Breadcrumbs
        elements={[
          { label: t_i18n('Data') },
          { label: t_i18n('Restriction') },
          { label: t_i18n('Restricted drafts'), current: true },
        ]}
        noMargin
      />
      <Alert
        content={t_i18n('This list displays all the drafts that have some access restriction enabled, meaning that they are only accessible to some specific users. You can remove this access restriction on this screen.')}
      />
      {queryRef && (
        <div style={{ overflow: 'hidden', flex: 1 }} ref={(r) => setRef(r ?? undefined)}>
          <DataTable
            rootRef={ref}
            dataColumns={isFeatureEnable('DRAFT_WORKFLOW') ? dataColumns : dataColumnsWithoutMetadata}
            resolvePath={(data: RestrictedDraftsLines_data$data) => (data.draftWorkspacesRestricted?.edges ?? []).map((n) => n?.node)}
            storageKey={LOCAL_STORAGE_KEY}
            initialValues={initialValues}
            contextFilters={contextFilters}
            preloadedPaginationProps={preloadedPaginationProps}
            lineFragment={RestrictedDraftLineFragment}
            disableBulkEnroll
            removeAuthMembersEnabled
          />
        </div>
      )}
    </>
  );
};

export default RestrictedDrafts;
