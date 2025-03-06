import React from 'react';
import AccessesMenu from '@components/settings/AccessesMenu';
import { graphql } from 'react-relay';
import {
  DisseminationListsLinesPaginationQuery,
  DisseminationListsLinesPaginationQuery$variables,
} from '@components/settings/dissemination_lists/__generated__/DisseminationListsLinesPaginationQuery.graphql';
import { DisseminationListsLine_node$data } from '@components/settings/dissemination_lists/__generated__/DisseminationListsLine_node.graphql';
import DisseminationListCreation from '@components/settings/dissemination_lists/DisseminationListCreation';
import DisseminationListPopover from '@components/settings/dissemination_lists/DisseminationListPopover';
import EnterpriseEdition from '@components/common/entreprise_edition/EnterpriseEdition';
import DataTable from '../../../../components/dataGrid/DataTable';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import ItemIcon from '../../../../components/ItemIcon';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import AlertInfo from '../../../../components/AlertInfo';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import PageContainer from '../../../../components/PageContainer';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';

export const disseminationListsQuery = graphql`
  query DisseminationListsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: DisseminationListOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...DisseminationListsLines_data
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

export const disseminationListsFragment = graphql`
  fragment DisseminationListsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "DisseminationListOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  ) @refetchable(queryName: "DisseminationListsLinesRefetchQuery") {
    disseminationLists(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_disseminationLists") {
      edges {
        node {
          ...DisseminationListsLine_node
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

const disseminationListsLineFragment = graphql`
  fragment DisseminationListsLine_node on DisseminationList {
    id
    name
    emails
    description
  }
`;

const LOCAL_STORAGE_KEY = 'view-dissemination-lists';

const DisseminationLists = () => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Dissemination lists | Security | Settings'));

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
  } = usePaginationLocalStorage<DisseminationListsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const { filters } = viewStorage;
  const contextFilters = useBuildEntityTypeBasedFilterContext('DisseminationList', filters);

  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as DisseminationListsLinesPaginationQuery$variables;

  const queryRef = useQueryLoading<DisseminationListsLinesPaginationQuery>(
    disseminationListsQuery,
    queryPaginationOptions,
  );

  const dataColumns: DataTableProps['dataColumns'] = {
    icon: {
      id: 'icon',
      label: ' ',
      isSortable: false,
      percentWidth: 5,
      render: () => <ItemIcon type="dissemination-list" />,
    },
    name: {
      id: 'name',
      label: 'Name',
      isSortable: true,
      percentWidth: 20,
    },
    description: {
      id: 'description',
      label: 'Description',
      percentWidth: 60,
      isSortable: false,
    },
    lineNumber: {
      id: 'dissemination_list_values_count',
      label: 'Number of recipients',
      percentWidth: 15,
      isSortable: true,
      render: (node: DisseminationListsLine_node$data) => node.emails.length || '-',
    },
  };

  const preloadedPaginationProps = {
    linesQuery: disseminationListsQuery,
    linesFragment: disseminationListsFragment,
    queryRef,
    nodePath: ['disseminationLists', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<DisseminationListsLinesPaginationQuery>;

  return (
    <>
      <AccessesMenu/>
      <PageContainer withRightMenu>
        <Breadcrumbs elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Security') }, { label: t_i18n('Dissemination lists'), current: true }]} />
        {!isEnterpriseEdition ? (
          <EnterpriseEdition feature="Dissemination lists" />
        ) : (
          <>
            <AlertInfo
              style={{ marginBottom: '16px' }}
              content={t_i18n('Dissemination lists can be used to send files to a list of recipients that do not necessarily have an OpenCTI account.')}
            />
            {queryRef && (
              <DataTable
                dataColumns={dataColumns}
                resolvePath={(data) => data.disseminationLists?.edges?.map(({ node }: { node: DisseminationListsLine_node$data }) => node)}
                storageKey={LOCAL_STORAGE_KEY}
                initialValues={initialValues}
                toolbarFilters={contextFilters}
                lineFragment={disseminationListsLineFragment}
                disableLineSelection
                disableNavigation
                preloadedPaginationProps={preloadedPaginationProps}
                actions={(row) => <DisseminationListPopover data={row} paginationOptions={queryPaginationOptions} />}
              />
            )}
            <DisseminationListCreation paginationOptions={queryPaginationOptions} />
          </>
        )}
      </PageContainer>
    </>
  );
};

export default DisseminationLists;
