import { useFormatter } from '../../../../components/i18n';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import AccessesMenu from '@components/settings/AccessesMenu';
import React from 'react';
import { graphql } from 'react-relay';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import DataTable from '../../../../components/dataGrid/DataTable';
import { SSODefinitionsLinesPaginationQuery } from '@components/settings/__generated__/SSODefinitionsLinesPaginationQuery.graphql';
import { SSODefinitionsLines_data$data } from '@components/settings/__generated__/SSODefinitionsLines_data.graphql';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import SSODefinitionCreation from '@components/settings/sso_definitions/SSODefinitionCreation';

const LOCAL_STORAGE_KEY = 'SSODefinitions';

export const ssoDefinitionsLinesQuery = graphql`
  query SSODefinitionsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: SingleSignOnOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...SSODefinitionsLines_data
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

const ssoDefinitionsLineFragment = graphql`
  fragment SSODefinitionsLine_node on SingleSignOn {
    id
    name
    entity_type
    identifier
    label
    description
    enabled
    strategy
    organizations_management {
      organizations_path
      organizations_mapping
    }
    groups_management{
      group_attributes
      groups_path
      groups_mapping
      read_userinfo
    }
    configuration {
      key
      value
      type
    }
  }
`;
const ssoDefinitionsLinesFragment = graphql`
  fragment SSODefinitionsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: {
        type: "SingleSignOnOrdering"
        defaultValue: name
    }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "SingleSignOnsLinesRefetchQuery") {
    singleSignOns(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_singleSignOns") {
      edges {
        node {
          id
          entity_type
          ...SSODefinitionsLine_node
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
const SSODefinitions = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('SSO Definitions | Security | Settings'));
  const initialValues = {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    filters: emptyFilterGroup,
  };
  const { viewStorage: { filters }, helpers, paginationOptions } = usePaginationLocalStorage<SSODefinitionsLinesPaginationQuery>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  const contextFilters = useBuildEntityTypeBasedFilterContext('SingleSignOn', filters);
  const queryPaginationOptions = { ...paginationOptions, filters: contextFilters };

  const dataColumns = {
    strategy: {
      label: 'Authentication strategy',
      percentWidth: 25,
      render: (node: { strategy: string }) => <div>{node.strategy}</div>,
    },
    name: {
      label: 'Configuration name',
      percentWidth: 25,
      render: (node: { identifier: string }) => <div>{node.identifier}</div>,
    },
    enabled: {
      label: 'Enabled',
      percentWidth: 25,
      render: (node: { enabled: boolean }) => <div>{JSON.stringify(node.enabled)}</div>,
    },
    label: {
      label: 'Login Name Button',
      percentWidth: 25,
      render: (node: { label: string }) => <div>{node.label}</div>,
    },
  };

  const queryRef = useQueryLoading(
    ssoDefinitionsLinesQuery,
    queryPaginationOptions,
  );

  const preloadedPaginationProps = {
    linesQuery: ssoDefinitionsLinesQuery,
    linesFragment: ssoDefinitionsLinesFragment,
    queryRef,
    nodePath: ['singleSignOns', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<SSODefinitionsLinesPaginationQuery>;

  return (
    <div style={{ paddingRight: '200px' }}>
      <Breadcrumbs elements={[
        { label: t_i18n('Settings') },
        { label: t_i18n('Security') },
        { label: t_i18n('SSO definitions'), current: true }]}
      />
      <AccessesMenu />
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: SSODefinitionsLines_data$data) => data.singleSignOns?.edges?.map((e) => e?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          contextFilters={contextFilters}
          lineFragment={ssoDefinitionsLineFragment}
          preloadedPaginationProps={preloadedPaginationProps}
          // actions={(ssoDefinition) => (
          //   <SSODefinitionPopover
          //     ssoDefinition={ssoDefinition}
          //     paginationOptions={queryPaginationOptions}
          //   />
          // )}
          entityTypes={['SingleSignOn']}
          searchContextFinal={{ entityTypes: ['SingleSignOn'] }}
          disableToolBar
          removeSelectAll
          createButton={<SSODefinitionCreation paginationOptions={queryPaginationOptions} />}
        />
      )}
    </div>
  );
};

export default SSODefinitions;
