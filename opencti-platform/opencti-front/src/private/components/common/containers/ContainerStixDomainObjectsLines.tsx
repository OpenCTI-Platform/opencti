import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { ContainerStixDomainObjectLine_node$data } from '@components/common/containers/__generated__/ContainerStixDomainObjectLine_node.graphql';
import {
  ContainerStixDomainObjectsLinesQuery,
  ContainerStixDomainObjectsLinesQuery$variables,
} from '@components/common/containers/__generated__/ContainerStixDomainObjectsLinesQuery.graphql';
import { ContainerStixDomainObjectsLines_container$key } from '@components/common/containers/__generated__/ContainerStixDomainObjectsLines_container.graphql';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { ContainerStixDomainObjectLine, ContainerStixDomainObjectLineDummy } from './ContainerStixDomainObjectLine';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import ContainerAddStixCoreObjects from './ContainerAddStixCoreObjects';
import { DataColumns } from '../../../../components/list_lines';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';

const nbOfRowsToLoad = 50;

interface ContainerStixDomainObjectsLinesProps {
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  dataColumns: DataColumns;
  paginationOptions: ContainerStixDomainObjectsLinesQuery$variables;
  queryRef: PreloadedQuery<ContainerStixDomainObjectsLinesQuery>;
  selectedElements: Record<string, ContainerStixDomainObjectLine_node$data>;
  deSelectedElements: Record<string, ContainerStixDomainObjectLine_node$data>;
  onToggleEntity: (
    entity: ContainerStixDomainObjectLine_node$data,
    event: React.SyntheticEvent
  ) => void;
  selectAll: boolean;
  onLabelClick?: HandleAddFilter;
  redirectionMode?: string;
  onTypesChange: (type: string) => void;
  openExports?: boolean,
  enableReferences?: boolean;
}

export const containerStixDomainObjectsLinesQuery = graphql`
  query ContainerStixDomainObjectsLinesQuery(
    $id: String!
    $search: String
    $types: [String]
    $count: Int!
    $cursor: ID
    $orderBy: StixObjectOrStixRelationshipsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...ContainerStixDomainObjectsLines_container
    @arguments(
      search: $search
      types: $types
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

export const containerStixDomainObjectsLinesFragment = graphql`
  fragment ContainerStixDomainObjectsLines_container on Query
  @argumentDefinitions(
    types: { type: "[String]" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: {
      type: "StixObjectOrStixRelationshipsOrdering"
      defaultValue: name
    }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "ContainerStixDomainObjectsLinesRefetchQuery") {
    container(id: $id) {
      id
      confidence
      createdBy {
        ... on Identity {
          id
          name
          entity_type
        }
      }
      objectMarking {
        id
        definition_type
        definition
        x_opencti_order
        x_opencti_color
      }
      objects(
        types: $types
        search: $search
        first: $count
        after: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
        filters: $filters
      ) @connection(key: "Pagination_objects") {
        edges {
          types
          node {
            ... on BasicObject {
              id
              entity_type
            }
            ...ContainerStixDomainObjectLine_node
          }
        }
        pageInfo {
          endCursor
          hasNextPage
          globalCount
        }
      }
    }
  }
`;

const ContainerStixDomainObjectsLines: FunctionComponent<ContainerStixDomainObjectsLinesProps> = ({
  dataColumns,
  onToggleEntity,
  selectedElements,
  deSelectedElements,
  selectAll,
  paginationOptions,
  setNumberOfElements,
  queryRef,
  onTypesChange,
  openExports,
  enableReferences,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  ContainerStixDomainObjectsLinesQuery,
  ContainerStixDomainObjectsLines_container$key
  >({
    linesQuery: containerStixDomainObjectsLinesQuery,
    linesFragment: containerStixDomainObjectsLinesFragment,
    queryRef,
    nodePath: ['container', 'objects', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  const { container } = data;
  const currentSelection = container?.objects?.edges ?? [];
  const selectWithoutInferred = currentSelection.filter((edge) => (edge?.types ?? ['manual']).includes('manual'));
  return (
    <div>
      <ListLinesContent
        initialLoading={!container}
        isLoading={isLoadingMore}
        loadMore={loadMore}
        hasMore={hasMore}
        dataList={container?.objects?.edges ?? []}
        paginationOptions={paginationOptions}
        globalCount={
          container?.objects?.pageInfo?.globalCount ?? nbOfRowsToLoad
        }
        LineComponent={
          <ContainerStixDomainObjectLine
            containerId={container?.id ?? null}
          />
        }
        DummyLineComponent={<ContainerStixDomainObjectLineDummy/>}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        selectedElements={selectedElements}
        deSelectedElements={deSelectedElements}
        selectAll={selectAll}
        onToggleEntity={onToggleEntity}
      />
      {container && (
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <ContainerAddStixCoreObjects
            containerId={container.id}
            containerStixCoreObjects={selectWithoutInferred}
            paginationOptions={paginationOptions}
            withPadding={true}
            targetStixCoreObjectTypes={['Stix-Domain-Object']}
            onTypesChange={onTypesChange}
            openExports={openExports}
            defaultCreatedBy={container.createdBy ?? null}
            defaultMarkingDefinitions={container.objectMarking ?? []}
            confidence={container.confidence}
            enableReferences={enableReferences}
          />
        </Security>
      )}
    </div>
  );
};

export default ContainerStixDomainObjectsLines;
