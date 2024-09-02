import React, { FunctionComponent } from 'react';
import useHelper from 'src/utils/hooks/useHelper';
import { graphql } from 'react-relay';
import {
  ExternalReferencesLinesPaginationQuery,
  ExternalReferencesLinesPaginationQuery$variables,
} from '@components/analyses/__generated__/ExternalReferencesLinesPaginationQuery.graphql';
import { ExternalReferencesLines_data$data } from '@components/analyses/__generated__/ExternalReferencesLines_data.graphql';
import ExternalReferenceCreation from './external_references/ExternalReferenceCreation';
import Security from '../../../utils/Security';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import useAuth from '../../../utils/hooks/useAuth';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import DataTable from '../../../components/dataGrid/DataTable';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';

const LOCAL_STORAGE_KEY = 'externalReferences';

interface ExternalReferencesProps {
  history: History;
  location: Location;
}

const externalReferencesLineFragment = graphql`
  fragment ExternalReferencesLine_node on ExternalReference {
    id
    entity_type
    source_name
    external_id
    url
    created
    creators {
      id
      name
    }
  }
`;

const externalReferencesLinesQuery = graphql`
  query ExternalReferencesLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: ExternalReferencesOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...ExternalReferencesLines_data
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

const externalReferencesLinesFragment = graphql`
  fragment ExternalReferencesLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "ExternalReferencesOrdering", defaultValue: source_name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "ExternalReferencesLinesRefetchQuery") {
    externalReferences(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_externalReferences") {
      edges {
        node {
          ...ExternalReferencesLine_node
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

const ExternalReferences: FunctionComponent<ExternalReferencesProps> = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('External references | Analyses'));
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();

  const initialValues = {
    searchTerm: '',
    sortBy: 'created',
    orderAsc: true,
    openExports: false,
    filters: emptyFilterGroup,
  };
  const { viewStorage, helpers: storageHelpers, paginationOptions } = usePaginationLocalStorage<ExternalReferencesLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  const { filters } = viewStorage;

  const contextFilters = useBuildEntityTypeBasedFilterContext('External-Reference', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as ExternalReferencesLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<ExternalReferencesLinesPaginationQuery>(
    externalReferencesLinesQuery,
    queryPaginationOptions,
  );
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const dataColumns: DataTableProps['dataColumns'] = {
    source_name: {},
    external_id: {},
    url: {},
    creator: {
      percentWidth: 15,
      isSortable: isRuntimeSort,
    },
    created: {},
  };

  const preloadedPaginationProps = {
    linesQuery: externalReferencesLinesQuery,
    linesFragment: externalReferencesLinesFragment,
    queryRef,
    nodePath: ['externalReferences', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<ExternalReferencesLinesPaginationQuery>;
  return (
    <>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Analyses') }, { label: t_i18n('External references'), current: true }]} />
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: ExternalReferencesLines_data$data) => data.externalReferences?.edges?.map((n) => n?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          preloadedPaginationProps={preloadedPaginationProps}
          lineFragment={externalReferencesLineFragment}
          entityTypes={['External-Reference']}
          createButton={isFABReplaced && (
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <ExternalReferenceCreation
                paginationOptions={queryPaginationOptions}
                openContextual={false}
              />
            </Security>
          )}
        />
      )}
      {!isFABReplaced && (
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <ExternalReferenceCreation
            paginationOptions={queryPaginationOptions}
            openContextual={false}
          />
        </Security>
      )}
    </>
  );
};

export default ExternalReferences;
