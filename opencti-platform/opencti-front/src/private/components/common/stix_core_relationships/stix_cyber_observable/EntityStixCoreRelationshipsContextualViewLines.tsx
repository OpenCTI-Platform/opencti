import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { UseLocalStorageHelpers } from '../../../../../utils/hooks/useLocalStorage';
import { UseEntityToggle } from '../../../../../utils/hooks/useEntityToggle';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import usePreloadedPaginationFragment from '../../../../../utils/hooks/usePreloadedPaginationFragment';
import ListLinesContent from '../../../../../components/list_lines/ListLinesContent';
import Loader, { LoaderVariant } from '../../../../../components/Loader';
import { DataColumns } from '../../../../../components/list_lines';
import { EntityStixCoreRelationshipsContextualViewLine, EntityStixCoreRelationshipsContextualViewLineDummy } from './EntityStixCoreRelationshipsContextualViewLine';
import {
  EntityStixCoreRelationshipsContextualViewLinesQuery, EntityStixCoreRelationshipsContextualViewLinesQuery$variables,
} from './__generated__/EntityStixCoreRelationshipsContextualViewLinesQuery.graphql';
import { EntityStixCoreRelationshipsContextualViewLine_node$data } from './__generated__/EntityStixCoreRelationshipsContextualViewLine_node.graphql';
import { EntityStixCoreRelationshipsContextualViewLines_data$key } from './__generated__/EntityStixCoreRelationshipsContextualViewLines_data.graphql';

const nbOfRowsToLoad = 50;

const contextualViewLinesFragment = graphql`
  fragment EntityStixCoreRelationshipsContextualViewLines_data on Query
  @argumentDefinitions(
    fromId: { type: "String!" }
    entityTypes: { type: "[String!]!" }
    containerType: { type: "String!" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "StixCoreObjectsOrdering", defaultValue: created_at }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "[StixCoreObjectsFiltering]" }
  )
  @refetchable(queryName: "ContextualViewLines_refetch") {
    stixDomainObjectsRelatedObjectsFromContainer(
      fromId: $fromId
      entityTypes: $entityTypes
      containerType: $containerType
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_stixDomainObjectsRelatedObjectsFromContainer") {
      edges {
        node {
          id
          ...EntityStixCoreRelationshipsContextualViewLine_node
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

export const contextualViewLinesQuery = graphql`
  query EntityStixCoreRelationshipsContextualViewLinesQuery(
    $fromId: String!
    $entityTypes: [String!]!
    $containerType: String!
    $search: String
    $count: Int!
    $cursor: ID
    $filters: [StixCoreObjectsFiltering]
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
  ) {
    ...EntityStixCoreRelationshipsContextualViewLines_data
    @arguments(
      fromId: $fromId
      entityTypes: $entityTypes
      containerType: $containerType
      search: $search
      count: $count
      cursor: $cursor
      filters: $filters
      orderBy: $orderBy
      orderMode: $orderMode
    )
  }
`;

interface EntityStixCoreRelationshipsContextualViewLinesProps {
  queryRef: PreloadedQuery<EntityStixCoreRelationshipsContextualViewLinesQuery>
  dataColumns: DataColumns
  entityId: string
  entityTypes: string[]
  containerType: string
  entityLink: string
  paginationOptions: Partial<EntityStixCoreRelationshipsContextualViewLinesQuery$variables>
  onToggleEntity: UseEntityToggle<EntityStixCoreRelationshipsContextualViewLine_node$data>['onToggleEntity']
  selectedElements: UseEntityToggle<EntityStixCoreRelationshipsContextualViewLine_node$data>['selectedElements']
  deSelectedElements: UseEntityToggle<EntityStixCoreRelationshipsContextualViewLine_node$data>['deSelectedElements']
  selectAll: UseEntityToggle<EntityStixCoreRelationshipsContextualViewLine_node$data>['selectAll']
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements']
}

const EntityStixCoreRelationshipsContextualViewLinesComponent: FunctionComponent<EntityStixCoreRelationshipsContextualViewLinesProps> = ({
  queryRef,
  dataColumns,
  entityLink,
  paginationOptions,
  onToggleEntity,
  selectedElements,
  deSelectedElements,
  selectAll,
  setNumberOfElements,
}) => {
  const { data, loadMore, hasMore, isLoadingMore } = usePreloadedPaginationFragment<
  EntityStixCoreRelationshipsContextualViewLinesQuery,
  EntityStixCoreRelationshipsContextualViewLines_data$key
  >({
    queryRef,
    linesQuery: contextualViewLinesQuery,
    linesFragment: contextualViewLinesFragment,
    nodePath: ['stixDomainObjectsRelatedObjectsFromContainer', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });

  return (
    <ListLinesContent
      initialLoading={false}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.stixDomainObjectsRelatedObjectsFromContainer?.edges ?? []}
      globalCount={
        data?.stixDomainObjectsRelatedObjectsFromContainer?.pageInfo?.globalCount ?? nbOfRowsToLoad
      }
      LineComponent={EntityStixCoreRelationshipsContextualViewLine}
      DummyLineComponent={EntityStixCoreRelationshipsContextualViewLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
      entityLink={entityLink}
      selectedElements={selectedElements}
      deSelectedElements={deSelectedElements}
      selectAll={selectAll}
      onToggleEntity={onToggleEntity}
    />
  );
};

const EntityStixCoreRelationshipsContextualViewLines: FunctionComponent<
Omit<EntityStixCoreRelationshipsContextualViewLinesProps, 'queryRef'>
> = (props) => {
  const { entityId, entityTypes, containerType, paginationOptions } = props;
  const queryRef = useQueryLoading<EntityStixCoreRelationshipsContextualViewLinesQuery>(
    contextualViewLinesQuery,
    {
      fromId: entityId,
      entityTypes,
      containerType,
      count: 25,
      ...paginationOptions,
    },
  );
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <EntityStixCoreRelationshipsContextualViewLinesComponent {...props} queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default EntityStixCoreRelationshipsContextualViewLines;
