import { graphql } from 'react-relay';
import React from 'react';
import CustomizationMenu from '@components/settings/CustomizationMenu';
import {
  FintelDesignsLinesPaginationQuery,
  FintelDesignsLinesPaginationQuery$variables,
} from '@components/settings/fintel_design/__generated__/FintelDesignsLinesPaginationQuery.graphql';
import FintelDesignCreation from '@components/settings/fintel_design/FintelDesignCreation';
import { FintelDesignsLines_data$data } from '@components/settings/fintel_design/__generated__/FintelDesignsLines_data.graphql';
import { FintelDesignsLine_node$data } from '@components/settings/fintel_design/__generated__/FintelDesignsLine_node.graphql';
import EnterpriseEdition from '@components/common/entreprise_edition/EnterpriseEdition';
import { useFormatter } from '../../../../components/i18n';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import DataTable from '../../../../components/dataGrid/DataTable';
import ItemIcon from '../../../../components/ItemIcon';
import PageContainer from '../../../../components/PageContainer';
import Alert from '../../../../components/Alert';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';

const fintelDesignsQuery = graphql`
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
          id
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
    file_id
    description
    gradiantFromColor
    gradiantToColor
    textColor
  }
`;

const LOCAL_STORAGE_KEY = 'view-fintel-designs';

const FintelDesigns = () => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Fintel design | Customization | Settings'));
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
      percentWidth: 40,
      isSortable: true,
    },
    description: {
      id: 'description',
      label: t_i18n('Description'),
      percentWidth: 60,
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

  const getRedirectionLink = (fintelDesignId: FintelDesignsLine_node$data) => {
    return `${fintelDesignId.id}`;
  };

  return (
    <div data-testid="fintel-designs-page">
      <CustomizationMenu />
      <PageContainer withGap withRightMenu >
        <Breadcrumbs
          noMargin
          elements={[
            { label: t_i18n('Settings') },
            { label: t_i18n('Customization') },
            { label: t_i18n('Fintel design'), current: true },
          ]}
        />
        {!isEnterpriseEdition ? (
          <EnterpriseEdition feature="Fintel design" />
        ) : (
          <>
            <Alert
              content={t_i18n('If no design configuration is detected, the default settings will be applied.')}
            />
            {queryRef && (
            <DataTable
              dataColumns={dataColumns}
              resolvePath={(data: FintelDesignsLines_data$data) => data.fintelDesigns?.edges?.map((n) => n?.node)}
              storageKey={LOCAL_STORAGE_KEY}
              initialValues={initialValues}
              contextFilters={contextFilters}
              getComputeLink={getRedirectionLink}
              lineFragment={fintelDesignsLineFragment}
              disableLineSelection
              preloadedPaginationProps={preloadedPaginationProps}
              createButton={<FintelDesignCreation paginationOptions={queryPaginationOptions} />}
              icon={() => <ItemIcon type="FintelDesign" />}
            />
            )}
          </>
        )}
      </PageContainer>
    </div>
  );
};

export default FintelDesigns;
