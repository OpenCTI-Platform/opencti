import React from 'react';
import { graphql } from 'react-relay';
import { CitizenshipDocumentsPaginationQuery, CitizenshipDocumentsPaginationQuery$variables } from '@components/entities/__generated__/CitizenshipDocumentsPaginationQuery.graphql';
import { citizenshipDocumentFragment } from '@components/entities/citizenshipDocuments/CitizenshipDocument';
import { CitizenshipDocumentLines_data$data } from '@components/entities/__generated__/CitizenshipDocumentLines_data.graphql';
import CitizenshipDocumentCreation from '@components/entities/citizenshipDocuments/CitizenshipDocumentCreation';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import DataTable from '../../../components/dataGrid/DataTable';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import { CITIZENSHIP_DOCUMENT_ENTITY_TYPE } from './citizenshipDocuments/CitizenshipDocumentUtils';

const LOCAL_STORAGE_KEY = 'citizenshipDocument';

export const citizenshipDocumentsQuery = graphql`
  query CitizenshipDocumentsPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: CitizenshipDocumentOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...CitizenshipDocumentLines_data
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

export const citizenshipDocumentsFragment = graphql`
  fragment CitizenshipDocumentLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "CitizenshipDocumentOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "CitizenshipDocumentLinesRefetchQuery") {
    citizenshipDocuments(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_citizenshipDocuments") {
      edges {
        node {
          id
          name
          description
          x_opencti_citizenship_document_type
          ...CitizenshipDocument_citizenshipDocument
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

const CitizenshipDocument = () => {
  const { t_i18n } = useFormatter();
  const initialValues = {
    filters: emptyFilterGroup,
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
  };
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Citizenship document'));
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<CitizenshipDocumentsPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const contextFilters = useBuildEntityTypeBasedFilterContext('Citizenship-Document', viewStorage.filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as CitizenshipDocumentsPaginationQuery$variables;

  const queryRef = useQueryLoading<CitizenshipDocumentsPaginationQuery>(
    citizenshipDocumentsQuery,
    queryPaginationOptions,
  );
  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      percentWidth: 20,
    },
    x_opencti_citizenship_document_type: {
      percentWidth: 20,
      label: 'document type',
    },
    objectLabel: {
      percentWidth: 20,
    },
    modified: {
      percentWidth: 20,
    },
    created_at: {
      percentWidth: 20,
    },
  };

  const preloadedPaginationProps = {
    linesQuery: citizenshipDocumentsQuery,
    linesFragment: citizenshipDocumentsFragment,
    queryRef,
    nodePath: ['citizenshipDocuments', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<CitizenshipDocumentsPaginationQuery>;

  return (
    <div data-testid="citizenship-document-page">
      <Breadcrumbs elements={[{ label: t_i18n('Entities') }, { label: t_i18n('Citizenship documents'), current: true }]} />
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: CitizenshipDocumentLines_data$data) => data.citizenshipDocuments?.edges?.map((n) => n?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          contextFilters={contextFilters}
          preloadedPaginationProps={preloadedPaginationProps}
          lineFragment={citizenshipDocumentFragment}
          exportContext={{ entity_type: CITIZENSHIP_DOCUMENT_ENTITY_TYPE }}
          createButton={(
            <CitizenshipDocumentCreation
              paginationOptions={queryPaginationOptions}
            />
          )}
        />
      )}
    </div>
  );
};

export default CitizenshipDocument;
