import { useState } from 'react';
import { graphql } from 'react-relay';
import AlertInfo from '../../../../components/Alert';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import DataTable from '../../../../components/dataGrid/DataTable';
import { useFormatter } from '../../../../components/i18n';
import { addFilter, emptyFilterGroup, useBuildEntityTypeBasedFilterContext, useGetDefaultFilterObject } from '../../../../utils/filters/filtersUtils';
import useAuth from '../../../../utils/hooks/useAuth';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import EnterpriseEdition from '../../common/entreprise_edition/EnterpriseEdition';
import { RestrictedEntitiesLinesPaginationQuery, RestrictedEntitiesLinesPaginationQuery$variables } from './__generated__/RestrictedEntitiesLinesPaginationQuery.graphql';
import { RestrictedEntitiesLines_data$data } from './__generated__/RestrictedEntitiesLines_data.graphql';

const LOCAL_STORAGE_KEY = 'restrictedEntities';

export const managementDefinitionsLinesPaginationQuery = graphql`
  query RestrictedEntitiesLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...RestrictedEntitiesLines_data
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

const managementDefinitionLineFragment = graphql`
  fragment RestrictedEntitiesLine_node on StixCoreObject{
    id
    entity_type
    created_at
    updated_at
    ... on StixObject {
      representative {
        main
        secondary
      }
    }
    createdBy {
      ... on Identity {
        name
      }
    }
    ... on Container {
      authorized_members_activation_date
    }
    objectMarking {
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
      created
      modified
    }
    objectLabel {
      id
      value
      color
    }
    creators {
      id
      name
    }
  }
`;

const managementDefinitionsLinesFragment = graphql`
  fragment RestrictedEntitiesLines_data on Query
  @argumentDefinitions(
    types: { type: "[String]" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: {
      type: "StixCoreObjectsOrdering"
      defaultValue: entity_type
    }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "RestrictedEntitiesLinesRefetchQuery") {
    stixCoreObjectsRestricted(
      types: $types
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
    @connection(key: "Pagination_stixCoreObjectsRestricted") {
      edges {
        node {
          id
          entity_type
          ...RestrictedEntitiesLine_node
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

const RestrictedEntities = () => {
  const [ref, setRef] = useState<HTMLDivElement | undefined>(undefined);
  const { t_i18n } = useFormatter();

  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Restriction | Data'));

  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const isRuntimeSort = isRuntimeFieldEnable();

  const isEnterpriseEdition = useEnterpriseEdition();

  const initialValues = {
    filters: {
      ...emptyFilterGroup,
      filters: useGetDefaultFilterObject(['entity_type'], ['Stix-Core-Object']),
    },
    searchTerm: '',
    sortBy: 'entity_type',
    orderAsc: true,
    numberOfElements: {
      number: 0,
      symbol: '',
    },
  };

  const {
    viewStorage: { filters },
    paginationOptions,
    helpers,
  } = usePaginationLocalStorage<RestrictedEntitiesLinesPaginationQuery$variables>(LOCAL_STORAGE_KEY, initialValues);

  const contextFilters = useBuildEntityTypeBasedFilterContext('Stix-Domain-Object', filters);
  const toolbarFilters = addFilter(contextFilters, 'authorized_members.id', [], 'not_nil');

  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  };

  const dataColumns = {
    entity_type: {
      percentWidth: 10,
      isSortable: true,
    },
    name: {
      percentWidth: 15,
    },
    createdBy: {
      isSortable: isRuntimeSort,
      percentWidth: 10,
    },
    creator: {
      isSortable: isRuntimeSort,
      percentWidth: 10,
    },
    objectLabel: {
      percentWidth: 10,
    },
    created_at: {
      percentWidth: 20,
    },
    authorized_members_activation_date: {
      percentWidth: 15,
    },
    objectMarking: {
      percentWidth: 10,
      isSortable: isRuntimeSort,
    },
  };

  const queryRef = useQueryLoading(
    managementDefinitionsLinesPaginationQuery,
    { ...queryPaginationOptions, count: 25 },
  );

  const preloadedPaginationProps = {
    linesQuery: managementDefinitionsLinesPaginationQuery,
    linesFragment: managementDefinitionsLinesFragment,
    queryRef,
    nodePath: ['stixCoreObjectsRestricted', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<RestrictedEntitiesLinesPaginationQuery>;

  return isEnterpriseEdition ? (
    <>
      <Breadcrumbs
        elements={[
          { label: t_i18n('Data') },
          { label: t_i18n('Restriction') },
          { label: t_i18n('Restricted entities'), current: true },
        ]}
        noMargin
      />
      <AlertInfo
        content={t_i18n('This list displays all the entities that have some access restriction enabled, meaning that they are only accessible to some specific users. You can remove this access restriction on this screen.')}
      />
      {queryRef && (
        <div style={{ overflow: 'hidden', flex: 1 }} ref={(r) => setRef(r ?? undefined)}>
          <DataTable
            rootRef={ref}
            dataColumns={dataColumns}
            resolvePath={(data: RestrictedEntitiesLines_data$data) => data.stixCoreObjectsRestricted?.edges?.map((e) => e?.node)}
            storageKey={LOCAL_STORAGE_KEY}
            initialValues={initialValues}
            lineFragment={managementDefinitionLineFragment}
            preloadedPaginationProps={preloadedPaginationProps}
            toolbarFilters={toolbarFilters}
            entityTypes={['Stix-Core-Object']}
            searchContextFinal={{ entityTypes: ['Stix-Core-Object'] }}
            removeAuthMembersEnabled={true}
          />
        </div>
      )}
    </>
  ) : (
    <EnterpriseEdition feature={t_i18n('Authorized_members')} />
  );
};

export default RestrictedEntities;
