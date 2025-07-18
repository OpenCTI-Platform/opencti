import React from 'react';
import AccessesMenu from '@components/settings/AccessesMenu';
import { graphql } from 'react-relay';
import {
  DisseminationListsLinesPaginationQuery,
  DisseminationListsLinesPaginationQuery$variables,
} from '@components/settings/dissemination_lists/__generated__/DisseminationListsLinesPaginationQuery.graphql';
import { DisseminationListsLine_node$data } from '@components/settings/dissemination_lists/__generated__/DisseminationListsLine_node.graphql';
import DisseminationListCreation from '@components/settings/dissemination_lists/DisseminationListCreation';
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
import EmailTemplateCreation from "@components/settings/email_template/EmailTemplateCreation";

export const disseminationListsQuery = graphql`
    query EmailTemplatesLinesPaginationQuery(
        $search: String
        $count: Int!
        $cursor: ID
        $orderBy: DisseminationListOrdering
        $orderMode: OrderingMode
        $filters: FilterGroup
    ) {
        ...EmailTemplatesLines_data
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
    fragment EmailTemplatesLines_data on Query
    @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "DisseminationListOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: desc }
        filters: { type: "FilterGroup" }
    ) @refetchable(queryName: "EmailTemplatesLinesRefetchQuery") {
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
                    ...EmailTemplatesLine_node
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
    fragment EmailTemplatesLine_node on DisseminationList {
        id
        entity_type
        name
        emails
        description
    }
`;

const LOCAL_STORAGE_KEY = 'view-email-templates';

const EmailTemplates = () => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Email templates | Security | Settings'));

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
    name: {
      id: 'name',
      label: 'Name',
      isSortable: true,
      percentWidth: 25,
    },
    description: {
      id: 'description',
      label: 'Description',
      percentWidth: 53,
      isSortable: false,
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
        <Breadcrumbs elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Security') }, { label: t_i18n('Email templates'), current: true }]} />
        {!isEnterpriseEdition ? (
          <EnterpriseEdition feature="Email templates" />
        ) : (
          <>
            <AlertInfo
              style={{ marginBottom: '16px' }}
              content={t_i18n('These template emails are only used for one time email, not for notifications or dissemination.')}
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
              preloadedPaginationProps={preloadedPaginationProps}
              createButton={<EmailTemplateCreation paginationOptions={queryPaginationOptions} />}
              icon={() => <ItemIcon color={'#afb505'} type="email-templates" />}
            />
            )}
          </>
        )}
      </PageContainer>
    </>
  );
};

export default EmailTemplates;
