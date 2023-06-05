import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer, graphql } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import {
  ContainerStixDomainObjectLine,
  ContainerStixDomainObjectLineDummy,
} from './ContainerStixDomainObjectLine';
import { setNumberOfElements } from '../../../../utils/Number';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import ContainerAddStixCoreObjects from './ContainerAddStixCoreObjects';

const nbOfRowsToLoad = 50;

class ContainerStixDomainObjectsLines extends Component {
  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'objects',
      this.props.setNumberOfElements.bind(this),
      'container',
    );
  }

  render() {
    const {
      initialLoading,
      dataColumns,
      relay,
      container,
      paginationOptions,
      openExports,
      onToggleEntity,
      selectedElements,
      deSelectedElements,
      selectAll,
    } = this.props;
    const currentSelection = container?.objects?.edges ?? [];
    const selectWithoutInferred = currentSelection.filter((edge) => (edge.types ?? ['manual']).includes('manual'));
    return (
      <div>
        <ListLinesContent
          initialLoading={initialLoading}
          loadMore={relay.loadMore.bind(this)}
          hasMore={relay.hasMore.bind(this)}
          isLoading={relay.isLoading.bind(this)}
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
          DummyLineComponent={<ContainerStixDomainObjectLineDummy />}
          dataColumns={dataColumns}
          nbOfRowsToLoad={nbOfRowsToLoad}
          selectedElements={selectedElements}
          deSelectedElements={deSelectedElements}
          selectAll={selectAll}
          onToggleEntity={onToggleEntity.bind(this)}
        />
        {container && (
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <ContainerAddStixCoreObjects
              containerId={container.id}
              containerStixCoreObjects={selectWithoutInferred}
              paginationOptions={paginationOptions}
              withPadding={true}
              targetStixCoreObjectTypes={['Stix-Domain-Object']}
              onTypesChange={this.props.onTypesChange}
              openExports={openExports}
            />
          </Security>
        )}
      </div>
    );
  }
}

ContainerStixDomainObjectsLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  container: PropTypes.object,
  relay: PropTypes.object,
  initialLoading: PropTypes.bool,
  searchTerm: PropTypes.string,
  setNumberOfElements: PropTypes.func,
  onTypesChange: PropTypes.func,
  openExports: PropTypes.bool,
  onToggleEntity: PropTypes.func,
  selectedElements: PropTypes.object,
  deSelectedElements: PropTypes.object,
  selectAll: PropTypes.bool,
};

export const containerStixDomainObjectsLinesQuery = graphql`
  query ContainerStixDomainObjectsLinesQuery(
    $id: String!
    $search: String
    $types: [String]
    $count: Int!
    $cursor: ID
    $orderBy: StixObjectOrStixRelationshipsOrdering
    $orderMode: OrderingMode
    $filters: [StixObjectOrStixRelationshipsFiltering]
  ) {
    container(id: $id) {
      id
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
  }
`;

export default createPaginationContainer(
  ContainerStixDomainObjectsLines,
  {
    container: graphql`
      fragment ContainerStixDomainObjectsLines_container on Container
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
        filters: { type: "[StixObjectOrStixRelationshipsFiltering]" }
      ) {
        id
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
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.container && props.container.objects;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count, cursor }, fragmentVariables) {
      return {
        id: fragmentVariables.id,
        count,
        cursor,
        search: fragmentVariables.search,
        types: fragmentVariables.types,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
        filters: fragmentVariables.filters,
      };
    },
    query: containerStixDomainObjectsLinesQuery,
  },
);
