import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { DataColumns } from '../../../../components/list_lines';
import type { UseEntityToggle } from '../../../../utils/hooks/useEntityToggle';
import {
  EntityStixCoreRelationshipsEntitiesLine,
  EntityStixCoreRelationshipsEntitiesLineDummy,
} from './EntityStixCoreRelationshipsEntitiesLine';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import {
  EntityStixCoreRelationshipsEntitiesPaginationQuery,
  EntityStixCoreRelationshipsEntitiesPaginationQuery$variables,
} from './__generated__/EntityStixCoreRelationshipsEntitiesPaginationQuery.graphql';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import { EntityStixCoreRelationshipsEntities_data$key } from './__generated__/EntityStixCoreRelationshipsEntities_data.graphql';

const nbOfRowsToLoad = 50;

interface EntityStixCoreRelationshipsEntitiesProps {
  queryRef: PreloadedQuery<EntityStixCoreRelationshipsEntitiesPaginationQuery>;
  dataColumns: DataColumns;
  entityLink: string;
  paginationOptions: EntityStixCoreRelationshipsEntitiesPaginationQuery$variables;
  isRelationReversed: boolean;
  onLabelClick: HandleAddFilter;
  onToggleEntity: UseEntityToggle<{ id: string }>['onToggleEntity'];
  selectedElements: UseEntityToggle<{ id: string }>['selectedElements'];
  deSelectedElements: UseEntityToggle<{ id: string }>['deSelectedElements'];
  selectAll: UseEntityToggle<{ id: string }>['selectAll'];
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
}

const entityStixCoreRelationshipsEntitiesFragment = graphql`
  fragment EntityStixCoreRelationshipsEntities_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "StixCoreObjectsOrdering", defaultValue: created_at }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "[StixCoreObjectsFiltering]" }
    types: { type: "[String]" }
    relationship_type: { type: "[String]" }
    elementId: { type: "String" }
  )
  @refetchable(queryName: "EntityStixCoreRelationshipsEntities_refetch") {
    stixCoreObjects(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      types: $types
      relationship_type: $relationship_type
      elementId: $elementId
    ) @connection(key: "Pagination_stixCoreObjects") {
      edges {
        node {
          id
          ...EntityStixCoreRelationshipsEntitiesLine_node
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

export const entityStixCoreRelationshipsEntitiesQuery = graphql`
  query EntityStixCoreRelationshipsEntitiesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
    $filters: [StixCoreObjectsFiltering]
    $types: [String]
    $relationship_type: [String]
    $elementId: String
  ) {
    ...EntityStixCoreRelationshipsEntities_data
      @arguments(
        search: $search
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
        filters: $filters
        types: $types
        relationship_type: $relationship_type
        elementId: $elementId
      )
  }
`;

const EntityStixCoreRelationshipsEntitiesComponent: FunctionComponent<
EntityStixCoreRelationshipsEntitiesProps
> = ({
  queryRef,
  dataColumns,
  entityLink,
  paginationOptions,
  isRelationReversed,
  onLabelClick,
  onToggleEntity,
  selectedElements,
  deSelectedElements,
  selectAll,
  setNumberOfElements,
}) => {
  const { data, loadMore, hasMore, isLoadingMore } = usePreloadedPaginationFragment<
  EntityStixCoreRelationshipsEntitiesPaginationQuery,
  EntityStixCoreRelationshipsEntities_data$key
  >({
    queryRef,
    linesQuery: entityStixCoreRelationshipsEntitiesQuery,
    linesFragment: entityStixCoreRelationshipsEntitiesFragment,
    nodePath: ['stixCoreObjects', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      initialLoading={false}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.stixCoreObjects?.edges ?? []}
      globalCount={
        data?.stixCoreObjects?.pageInfo?.globalCount ?? nbOfRowsToLoad
      }
      LineComponent={EntityStixCoreRelationshipsEntitiesLine}
      DummyLineComponent={EntityStixCoreRelationshipsEntitiesLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
      entityLink={entityLink}
      isTo={isRelationReversed}
      onLabelClick={onLabelClick}
      selectedElements={selectedElements}
      deSelectedElements={deSelectedElements}
      selectAll={selectAll}
      onToggleEntity={onToggleEntity}
    />
  );
};

const EntityStixCoreRelationshipsEntities: FunctionComponent<
Omit<EntityStixCoreRelationshipsEntitiesProps, 'queryRef'>
> = (props) => {
  const queryRef = useQueryLoading<EntityStixCoreRelationshipsEntitiesPaginationQuery>(
    entityStixCoreRelationshipsEntitiesQuery,
    { count: 25, ...props.paginationOptions },
  );
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <EntityStixCoreRelationshipsEntitiesComponent
        {...props}
        queryRef={queryRef}
      />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default EntityStixCoreRelationshipsEntities;
