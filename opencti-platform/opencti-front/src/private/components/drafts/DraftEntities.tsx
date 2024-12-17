import React, { FunctionComponent, useEffect } from 'react';
import { DraftEntitiesLinesPaginationQuery, DraftEntitiesLinesPaginationQuery$variables } from '@components/drafts/__generated__/DraftEntitiesLinesPaginationQuery.graphql';
import { useParams } from 'react-router-dom';
import { DraftContextBannerMutation } from '@components/drafts/__generated__/DraftContextBannerMutation.graphql';
import { draftContextBannerMutation } from '@components/drafts/DraftContextBanner';
import { graphql } from 'react-relay';
import { DraftEntitiesLines_data$data } from '@components/drafts/__generated__/DraftEntitiesLines_data.graphql';
import useAuth from '../../../utils/hooks/useAuth';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { useBuildEntityTypeBasedFilterContext, emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { MESSAGING$ } from '../../../relay/environment';
import { RelayError } from '../../../relay/relayTypes';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import DataTable from '../../../components/dataGrid/DataTable';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';

const draftEntitiesLineFragment = graphql`
    fragment DraftEntities_node on StixCoreObject {
        id
        entity_type
        created_at
        representative {
          main
        }
        draftVersion {
          draft_operation
        }
        objectMarking {
            id
            definition
            x_opencti_order
            x_opencti_color
        }
        creators {
            id
            name
        }
    }
`;

const draftEntitiesLinesQuery = graphql`
    query DraftEntitiesLinesPaginationQuery(
        $draftId: String!
        $types: [String]
        $search: String
        $count: Int!
        $cursor: ID
        $orderBy: StixCoreObjectsOrdering
        $orderMode: OrderingMode
        $filters: FilterGroup
    ) {
        ...DraftEntitiesLines_data
        @arguments(
            draftId: $draftId
            types: $types
            search: $search
            count: $count
            cursor: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
            filters: $filters
        )
    }
`;

export const draftEntitiesLinesFragment = graphql`
    fragment DraftEntitiesLines_data on Query
    @argumentDefinitions(
        draftId: { type: "String!" }
        types: { type: "[String]" }
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "StixCoreObjectsOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "FilterGroup" }
    )
    @refetchable(queryName: "DraftEntitiesLinesRefetchQuery") {
        draftWorkspaceEntities(
            draftId: $draftId
            types: $types
            search: $search
            first: $count
            after: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
            filters: $filters
        ) @connection(key: "Pagination_draftWorkspaceEntities") {
            edges {
                node {
                    ...DraftEntities_node
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

const LOCAL_STORAGE_KEY = 'draft_entities';

interface DraftEntitiesProps {
  entitiesType?: string;
}

const DraftEntities : FunctionComponent<DraftEntitiesProps> = ({
  entitiesType = 'Stix-Core-Object',
}) => {
  const { draftId } = useParams() as { draftId: string };
  const { t_i18n } = useFormatter();
  const {
    me,
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const initialValues = {
    filters: emptyFilterGroup,
    searchTerm: '',
    sortBy: 'name',
    orderAsc: false,
    openExports: false,
    redirectionMode: 'overview',
    draftId,
  };

  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<DraftEntitiesLinesPaginationQuery$variables>(LOCAL_STORAGE_KEY, initialValues);
  const {
    filters,
  } = viewStorage;

  const contextFilters = useBuildEntityTypeBasedFilterContext(entitiesType, filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    draftId,
    filters: contextFilters,
  } as unknown as DraftEntitiesLinesPaginationQuery$variables;

  const queryRef = useQueryLoading<DraftEntitiesLinesPaginationQuery>(
    draftEntitiesLinesQuery,
    queryPaginationOptions,
  );

  const preloadedPaginationProps = {
    linesQuery: draftEntitiesLinesQuery,
    linesFragment: draftEntitiesLinesFragment,
    queryRef,
    nodePath: ['draftWorkspaceEntities', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<DraftEntitiesLinesPaginationQuery>;

  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const dataColumns: DataTableProps['dataColumns'] = {
    draftVersion: {
      isSortable: false,
      percentWidth: 10,
    },
    entity_type: {
      percentWidth: 12,
      isSortable: true,
    },
    name: {
      percentWidth: 25,
      isSortable: true,
    },
    createdBy: {
      percentWidth: 10,
      isSortable: isRuntimeSort,
    },
    creator: {
      percentWidth: 10,
      isSortable: isRuntimeSort,
    },
    objectLabel: {
      percentWidth: 15,
      isSortable: false,
    },
    created_at: {
      percentWidth: 10,
      isSortable: true,
    },
    objectMarking: {
      isSortable: isRuntimeSort,
      percentWidth: 8,
    },
  };

  const [commitSwitchToDraft] = useApiMutation<DraftContextBannerMutation>(draftContextBannerMutation);
  useEffect(() => {
    if (!me.draftContext || me.draftContext.id !== draftId) {
      commitSwitchToDraft({
        variables: {
          input: [{ key: 'draft_context', value: [draftId] }],
        },
        onCompleted: () => {
          MESSAGING$.notifySuccess(<span>{t_i18n('You are now in Draft Mode')}</span>);
        },
        onError: (error) => {
          const { errors } = (error as unknown as RelayError).res;
          MESSAGING$.notifyError(errors.at(0)?.message);
        },
      });
    }
  }, [commitSwitchToDraft]);

  return (
    <span data-testid="draft-entities-page">
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: DraftEntitiesLines_data$data) => data.draftWorkspaceEntities?.edges?.map((n) => n?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          preloadedPaginationProps={preloadedPaginationProps}
          lineFragment={draftEntitiesLineFragment}
          exportContext={{ entity_type: 'Stix-Domain-Object' }}
          redirectionModeEnabled
          disableSelectAll // TODO: To handle selectAll
        />
      )}
    </span>
  );
};

export default DraftEntities;
