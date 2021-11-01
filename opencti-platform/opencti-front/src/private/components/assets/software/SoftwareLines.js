import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { SoftwareLine, SoftwareLineDummy } from './SoftwareLine';
import { setNumberOfElements } from '../../../../utils/Number';

const nbOfRowsToLoad = 50;

class SoftwareLines extends Component {
  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'softwareAssetList',
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
        dataList={pathOr([], ['softwareAssetList', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['softwareAssetList', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<SoftwareLine />}
        DummyLineComponent={<SoftwareLineDummy />}
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

SoftwareLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  initialLoading: PropTypes.bool,
  onLabelClick: PropTypes.func,
  setNumberOfElements: PropTypes.func,
};

export const softwareLinesQuery = graphql`
  query SoftwareLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderedBy: SoftwareAssetOrdering
    $orderMode: OrderingMode
    $filters: [SoftwareAssetFiltering]
  ) {
    ...SoftwareLines_data
      @arguments(
        search: $search
        count: $count
        cursor: $cursor
        orderedBy: $orderedBy
        orderMode: $orderMode
        filters: $filters
      )
  }
`;

// export const softwareLinesdarkLightRootQuery = graphql`
//   query SoftwareLinesDarkLightQuery {
//     softwareAssetList {
//       edges {
//         node {
//           id
//           asset_type
//           name
//           asset_id
//           created
//           modified
//           vendor_name
//           version
//           patch_level
//           cpe_identifier
//           software_identifier
//           labels
//         }
//       }
//     }
//   }
// `;

export default createPaginationContainer(
  SoftwareLines,
  {
    data: graphql`
      fragment SoftwareLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderedBy: { type: "SoftwareAssetOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "[SoftwareAssetFiltering]" }
      ) {
        softwareAssetList(
          search: $search
          first: $count
          # after: $cursor
          orderedBy: $orderedBy
          orderMode: $orderMode
          filters: $filters
        ) @connection(key: "Pagination_softwareAssetList") {
          edges {
            node {
              id
              name
              description
              ...SoftwareLine_node
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
      return props.data && props.data.softwareAssetList;
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
        orderedBy: fragmentVariables.orderedBy,
        orderMode: fragmentVariables.orderMode,
        filters: fragmentVariables.filters,
      };
    },
    query: softwareLinesQuery,
  },
);
