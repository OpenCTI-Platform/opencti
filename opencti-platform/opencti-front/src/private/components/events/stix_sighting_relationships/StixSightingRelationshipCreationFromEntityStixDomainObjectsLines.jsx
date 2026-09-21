import React from 'react';
import { graphql } from 'react-relay';
import DataTable from '../../../../components/dataGrid/DataTable';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup } from '../../../../utils/filters/filtersUtils';
import ItemIcon from '../../../../components/ItemIcon';

const LOCAL_STORAGE_KEY = 'stixSightingRelationshipCreationFromEntity';

export const stixSightingRelationshipCreationFromEntityStixDomainObjectsLinesQuery = graphql`
  query StixSightingRelationshipCreationFromEntityStixDomainObjectsLinesQuery(
    $search: String
    $types: [String]
    $count: Int!
    $cursor: ID
    $orderBy: StixDomainObjectsOrdering
    $orderMode: OrderingMode
  ) {
    ...StixSightingRelationshipCreationFromEntityStixDomainObjectsLines_data
      @arguments(
        search: $search
        types: $types
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

export const stixSightingRelationshipCreationFromEntityStixDomainObjectsLinesFragment = graphql`
  fragment StixSightingRelationshipCreationFromEntityStixDomainObjectsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    types: { type: "[String]" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "StixDomainObjectsOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
  ) @refetchable(queryName: "StixSightingRelationshipCreationFromEntityStixDomainObjectsLinesRefetchQuery") {
    stixDomainObjects(
      search: $search
      types: $types
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
    ) @connection(key: "Pagination_stixDomainObjects") {
      edges {
        node {
          id
          entity_type
          parent_types
          ...StixSightingRelationshipCreationFromEntityStixDomainObjectsLine_node
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

export const stixSightingRelationshipCreationFromEntityStixDomainObjectsLineFragment = graphql`
  fragment StixSightingRelationshipCreationFromEntityStixDomainObjectsLine_node on StixDomainObject {
    id
    entity_type
    parent_types
    ... on AttackPattern { name description }
    ... on Campaign { name description }
    ... on CourseOfAction { name description }
    ... on Individual { name description }
    ... on Organization { name description }
    ... on Sector { name description }
    ... on System { name description }
    ... on SecurityPlatform { name description }
    ... on Indicator { name description }
    ... on Infrastructure { name description }
    ... on IntrusionSet { name description }
    ... on Position { name description }
    ... on City { name description }
    ... on AdministrativeArea { name description }
    ... on Country { name description }
    ... on Region { name description }
    ... on Malware { name description }
    ... on ThreatActor { name description }
    ... on Tool { name description }
    ... on Vulnerability { name description }
    ... on Incident { name description }
  }
`;

const StixSightingRelationshipCreationFromEntityStixDomainObjectsLines = ({
  handleSelect,
  search,
  stixCoreObjectTypes,
}) => {
  const initialValues = {
    filters: emptyFilterGroup,
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
  };
  const { viewStorage, helpers } = usePaginationLocalStorage(
    LOCAL_STORAGE_KEY,
    initialValues,
    true,
  );
  const queryRef = useQueryLoading(
    stixSightingRelationshipCreationFromEntityStixDomainObjectsLinesQuery,
    {
      search,
      types: stixCoreObjectTypes,
      count: 25,
      orderBy: viewStorage.sortBy,
      orderMode: viewStorage.orderAsc ? 'asc' : 'desc',
    },
  );

  if (!queryRef) return null;

  return (
    <DataTable
      dataColumns={{
        name: {
          label: 'Name',
          percentWidth: 100,
          isSortable: false,
          render: (row) => (
            <span style={{ color: 'var(--text-default)', fontSize: 14, fontWeight: 500 }}>
              {row.name}
            </span>
          ),
        },
      }}
      resolvePath={(data) => data.stixDomainObjects?.edges?.map((edge) => edge?.node)}
      storageKey={LOCAL_STORAGE_KEY}
      initialValues={initialValues}
      contextFilters={emptyFilterGroup}
      preloadedPaginationProps={{
        linesQuery: stixSightingRelationshipCreationFromEntityStixDomainObjectsLinesQuery,
        linesFragment: stixSightingRelationshipCreationFromEntityStixDomainObjectsLinesFragment,
        queryRef,
        nodePath: ['stixDomainObjects', 'pageInfo', 'globalCount'],
        setNumberOfElements: helpers.handleSetNumberOfElements,
      }}
      lineFragment={stixSightingRelationshipCreationFromEntityStixDomainObjectsLineFragment}
      entityTypes={stixCoreObjectTypes}
      disableNavigation
      disableLineSelection
      disableColumnMenu
      hideSearch
      hideSavedFilters
      onLineClick={handleSelect}
      icon={(row) => (
        <span style={{ display: 'flex', marginLeft: 8, transform: 'scale(1.15)' }}>
          <ItemIcon type={row.entity_type} />
        </span>
      )}
    />
  );
};

export default StixSightingRelationshipCreationFromEntityStixDomainObjectsLines;
