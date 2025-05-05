import { graphql } from 'react-relay';
import React from 'react';
import CustomizationMenu from '@components/settings/CustomizationMenu';
import { FintelDesignsLine_node$data } from '@components/settings/fintel_design/__generated__/FintelDesignsLine_node.graphql';
import {
  FintelDesignsLinesPaginationQuery,
  FintelDesignsLinesPaginationQuery$variables,
} from '@components/settings/fintel_design/__generated__/FintelDesignsLinesPaginationQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import DataTable from '../../../../components/dataGrid/DataTable';
import ItemIcon from '../../../../components/ItemIcon';

export const fintelDesignsQuery = graphql`
  query FintelDesignsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: FintelDesignOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...FintelDesignsLines_data
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

export const fintelDesignsFragment = graphql`
  fragment FintelDesignsLines_data on Query 
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "FintelDesignOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  ) @refetchable(queryName: "FintelDesignsLinesRefetchQuery") {
    fintelDesigns(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_fintelDesigns") {
      edges {
        node {
          ...FintelDesignsLine_node
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

const fintelDesignsLineFragment = graphql`
  fragment FintelDesignsLine_node on FintelDesign {
    id
    name
    description
    gradiantFromColor
    gradiantToColor
    textColor
  }
`;

const LOCAL_STORAGE_KEY = 'view-fintel-designs';

const FintelDesigns = () => {
  const { t_i18n } = useFormatter();

  const initialValues = {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
    filters: emptyFilterGroup,
  };

  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<FintelDesignsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const { filters } = viewStorage;
  const contextFilters = useBuildEntityTypeBasedFilterContext('FintelDesign', filters);

  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as FintelDesignsLinesPaginationQuery$variables;

  const queryRef = useQueryLoading<FintelDesignsLinesPaginationQuery>(
    fintelDesignsQuery,
    queryPaginationOptions,
  );

  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      id: 'name',
      label: t_i18n('Name'),
      isSortable: true,
      percentWidth: 20,
    },
    description: {
      id: 'description',
      label: t_i18n('Description'),
      percentWidth: 20,
      isSortable: false,
    },
  };

  const preloadedPaginationProps = {
    linesQuery: fintelDesignsQuery,
    linesFragment: fintelDesignsFragment,
    queryRef,
    nodePath: ['fintelDesigns', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<FintelDesignsLinesPaginationQuery>;

  return (
    <>
      <CustomizationMenu />
      <Breadcrumbs elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Customization') }, { label: t_i18n('Fintel Designs') }]} />
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data) => data.fintelDesigns?.edges?.map(({ node }: { node: FintelDesignsLine_node$data }) => node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          lineFragment={fintelDesignsLineFragment}
          preloadedPaginationProps={preloadedPaginationProps}
          actions={(row) => <div></div>}
          createButton={<div></div>}
          icon={() => <ItemIcon type="fintel-design" />}
        />
      )}
    </>
  );
};

export default FintelDesigns;
