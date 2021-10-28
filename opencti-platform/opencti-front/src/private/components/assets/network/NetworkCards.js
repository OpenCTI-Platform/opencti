import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListCardsContent from '../../../../components/list_cards/ListCardsContent';
import { NetworkCard, NetworkCardDummy } from './NetworkCard';
import { setNumberOfElements } from '../../../../utils/Number';
import { QueryRenderer } from '../../../../relay/environment';
import StixDomainObjectBookmarks, {
  stixDomainObjectBookmarksQuery,
} from '../../common/stix_domain_objects/StixDomainObjectBookmarks';

const nbOfCardsToLoad = 50;

class NetworkCards extends Component {
  constructor(props) {
    super(props);
    this.state = { bookmarks: [] };
  }

  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'networkAssetList',
      this.props.setNumberOfElements.bind(this),
    );
  }

  handleSetBookmarkList(bookmarks) {
    this.setState({ bookmarks });
  }

  render() {
    const {
      initialLoading,
      relay,
      selectAll,
      onLabelClick,
      onToggleEntity,
      selectedElements,
    } = this.props;
    const { bookmarks } = this.state;
    return (
    // <QueryRenderer
    //   query={stixDomainObjectBookmarksQuery}
    //   variables={{ types: ['Network'] }}
    //   render={({ props }) => (
    //     <div>
    //       <StixDomainObjectBookmarks
    //         data={props}
    //         onLabelClick={onLabelClick.bind(this)}
    //         setBookmarkList={this.handleSetBookmarkList.bind(this)}
    //       />
            <ListCardsContent
              initialLoading={initialLoading}
              loadMore={relay.loadMore.bind(this)}
              hasMore={relay.hasMore.bind(this)}
              isLoading={relay.isLoading.bind(this)}
              dataList={pathOr([], ['networkAssetList', 'edges'], this.props.data)}
              globalCount={pathOr(
                nbOfCardsToLoad,
                ['networkAssetList', 'pageInfo', 'globalCount'],
                this.props.data,
              )}
              CardComponent={<NetworkCard />}
              DummyCardComponent={<NetworkCardDummy />}
              selectAll={selectAll}
              nbOfCardsToLoad={nbOfCardsToLoad}
              selectedElements={selectedElements}
              onLabelClick={onLabelClick.bind(this)}
              onToggleEntity={onToggleEntity.bind(this)}
              bookmarkList={bookmarks}
            />
    //     </div>
    //   )}
    // />
    );
  }
}

NetworkCards.propTypes = {
  data: PropTypes.object,
  relay: PropTypes.object,
  initialLoading: PropTypes.bool,
  onLabelClick: PropTypes.func,
  setNumberOfElements: PropTypes.func,
};

export const networkCardsQuery = graphql`
  query NetworkCardsPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderedBy: NetworkAssetOrdering
    $orderMode: OrderingMode
    $filters: [NetworkAssetFiltering]
  ) {
    ...NetworkCards_data
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

// export const networkCardsdarkLightRootQuery = graphql`
//   query NetworkCardsDarkLightQuery {
//     networkAssetList {
//       edges {
//         node {
//           id
//           name
//           labels
//           asset_id
//           network_id
//           network_address_range {
//             ending_ip_address{
//               ... on IpV4Address {
//                 ip_address_value
//               }
//             }
//             starting_ip_address{
//               ... on IpV4Address {
//                 ip_address_value
//               }
//             }
//           }
//         }
//       }
//     }
//   }
// `;

export default createPaginationContainer(
  NetworkCards,
  {
    data: graphql`
      fragment NetworkCards_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderedBy: { type: "NetworkAssetOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "[NetworkAssetFiltering]" }
      ) {
        networkAssetList(
          search: $search
          first: $count
          # after: $cursor
          orderedBy: $orderedBy
          orderMode: $orderMode
          filters: $filters
        ) @connection(key: "Pagination_networkAssetList") {
          edges {
            node {
              id
              name
              description
              ...NetworkCard_node
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
      return props.data && props.data.networkAssetList;
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
    query: networkCardsQuery,
  },
);
