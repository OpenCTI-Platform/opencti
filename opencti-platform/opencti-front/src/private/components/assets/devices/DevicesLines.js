import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { DeviceLine, DeviceLineDummy } from './DeviceLine';
import { setNumberOfElements } from '../../../../utils/Number';

const nbOfRowsToLoad = 50;

class DevicesLines extends Component {
  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'threatActors',
      this.props.setNumberOfElements.bind(this),
    );
  }

  render() {
    const {
      relay,
      selectAll,
      dataColumns,
      onLabelClick,
      initialLoading,
      onToggleEntity,
      selectedElements,
    } = this.props;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['computingDeviceAssetList', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['threatActors', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<DeviceLine />}
        DummyLineComponent={<DeviceLineDummy />}
        selectAll={selectAll}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        selectedElements={selectedElements}
        onLabelClick={onLabelClick.bind(this)}
        onToggleEntity={onToggleEntity.bind(this)}
      />
    );
  }
}

DevicesLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  threatActors: PropTypes.object,
  initialLoading: PropTypes.bool,
  onLabelClick: PropTypes.func,
  setNumberOfElements: PropTypes.func,
};

export const devicesLinesQuery = graphql`
  query DevicesLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: ThreatActorsOrdering
    $orderMode: OrderingMode
    $filters: [ThreatActorsFiltering]
  ) {
    ...DevicesLines_data
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

// const deleteComputingDevicesMutation = graphql`
//   mutation DeleteComputingDeviceAssetMutation($deleteComputingDeviceAssetId: ID!) {
//     deleteComputingDeviceAsset(id: $deleteComputingDeviceAssetId)
//   }
// `;

export const devicesLinesdarkLightRootQuery = graphql`
  query DevicesLinesDarkLightQuery {
    computingDeviceAssetList {
      edges {
        node {
          id
          name
          installed_operating_system {
            name
          }
          asset_id
          fqdn
          network_id
          created
          modified
        }
      }
    }
  }
`;

export default createPaginationContainer(
  DevicesLines,
  {
    data: graphql`
      fragment DevicesLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "ThreatActorsOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "[ThreatActorsFiltering]" }
      ) {
        threatActors(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) @connection(key: "Pagination_threatActors") {
          edges {
            node {
              id
              name
              description
              ...DeviceLine_node
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
      return props.data && props.data.threatActors;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count, cursor }, fragmentVariables) {
      return {
        search: fragmentVariables.search,
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
        filters: fragmentVariables.filters,
      };
    },
    query: devicesLinesQuery,
  },
);
