import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { RiskLine, RiskLineDummy } from './RiskLine';
import { setNumberOfElements } from '../../../../utils/Number';

const nbOfRowsToLoad = 50;

class RisksLines extends Component {
  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'poamItems',
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
        dataList={pathOr([], ['poamItems', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['poamItems', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<RiskLine />}
        DummyLineComponent={<RiskLineDummy />}
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

RisksLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  threatActors: PropTypes.object,
  computingDeviceAssetList: PropTypes.object,
  initialLoading: PropTypes.bool,
  onLabelClick: PropTypes.func,
  setNumberOfElements: PropTypes.func,
};

export const risksLinesQuery = graphql`
  query RisksLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderedBy: POAMItemsOrdering
    $orderMode: OrderingMode
    $filters: [POAMItemsFiltering]
  ) {
    ...RisksLines_data
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

export default createPaginationContainer(
  RisksLines,
  {
    data: graphql`
      fragment RisksLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderedBy: { type: "POAMItemsOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "[POAMItemsFiltering]" }
      ) {
        poamItems(
          search: $search
          first: $count
          # after: $cursor
          offset: $count
          orderedBy: $orderedBy
          orderMode: $orderMode
          filters: $filters
        ) @connection(key: "Pagination_poamItems") {
          edges {
            node {
              id
              name
              description
              # related_risks {
              #   edges {
              #     node {
              #       characterizations {
              #         ... on VulnerabilityCharacterization {
              #           id
              #           vulnerability_id
              #           facets {
              #             id
              #             name
              #             value
              #           }
              #         }
              #         ... on RiskCharacterization {
              #           id
              #           risk
              #           risk_state
              #           likelihood
              #           impact
              #           facets {
              #             id
              #             name
              #             value
              #           }
              #         }
              #         ... on GenericCharacterization {
              #           id
              #           facets {
              #             id
              #             name
              #             value
              #           }
              #         }
              #       }
              #     }
              #   }
              # }
              # related_observations {
              #   edges {
              #     node {
              #       name
              #       subjects {
              #         subject_type
              #         subject {
              #           ... on OscalParty {
              #             name
              #             party_type
              #           }
              #           ... on Component {
              #             name
              #             component_type
              #           }
              #         }
              #       }
              #     }
              #   }
              # }
              ...RiskLine_node
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
      return props.data && props.data.poamItems;
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
    query: risksLinesQuery,
  },
);
