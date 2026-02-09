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
import { SSODefinitionsLinesPaginationQuery } from './__generated__/SSODefinitionsLinesPaginationQuery.graphql';
import { SSODefinitionsLines_data$data } from './__generated__/SSODefinitionsLines_data.graphql';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import SSODefinitionCreation from '@components/settings/sso_definitions/SSODefinitionCreation';
import ItemBoolean from '../../../../components/ItemBoolean';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import EnterpriseEdition from '@components/common/entreprise_edition/EnterpriseEdition';
import AuthenticationDefinitionAlert from '@components/settings/sso_definitions/AuthenticationDefinitionAlert';

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
      groups_attributes
      group_attributes
      group_attribute
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
    singleSignOnSettings {
      is_force_env
    }
  }
`;
const SSODefinitions = () => {
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Authentication Definitions | Security | Settings'));
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
      label: t_i18n('Authentication strategy'),
      percentWidth: 25,
      render: (node: { strategy: string }) => (
        <ItemBoolean
          neutralLabel={t_i18n(node.strategy)}
          status={null}
        />
      ),
    },
    name: {
      label: t_i18n('Configuration name'),
      percentWidth: 25,
      render: (node: { name: string }) => <div>{node.name}</div>,
    },
    enabled: {
      label: t_i18n('Enabled'),
      percentWidth: 25,
      render: (node: { enabled: boolean }) => (
        node.enabled
          ? <ItemBoolean label={t_i18n('True')} status={true} />
          : <ItemBoolean label={t_i18n('False')} status={false} />
      ) },
    label: {
      label: t_i18n('Login Button Name'),
      percentWidth: 25,
      render: (node: { label?: string; identifier: string }) => (
        <ItemBoolean
          neutralLabel={node?.label ?? node.identifier}
          status={null}
        />
      ) },
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
        { label: t_i18n('Authentication definitions'), current: true }]}
      />
      <AccessesMenu />
      {isEnterpriseEdition ? (
        <>
          {queryRef && (
            <>
              <AuthenticationDefinitionAlert preloadedPaginationProps={preloadedPaginationProps} />
              <DataTable
                dataColumns={dataColumns}
                resolvePath={(data: SSODefinitionsLines_data$data) => data.singleSignOns?.edges?.map((e) => e?.node)}
                storageKey={LOCAL_STORAGE_KEY}
                initialValues={initialValues}
                contextFilters={contextFilters}
                lineFragment={ssoDefinitionsLineFragment}
                preloadedPaginationProps={preloadedPaginationProps}
                entityTypes={['SingleSignOn']}
                searchContextFinal={{ entityTypes: ['SingleSignOn'] }}
                disableToolBar
                removeSelectAll
                disableLineSelection
                createButton={<SSODefinitionCreation paginationOptions={queryPaginationOptions} />}
              />
            </>
          )}
        </>
      ) : (
        <EnterpriseEdition feature="Authentication definitions" />
      )}
    </div>
  );
};

export default SSODefinitions;
