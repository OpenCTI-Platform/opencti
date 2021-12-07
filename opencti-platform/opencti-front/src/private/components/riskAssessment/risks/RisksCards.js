import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import CyioListCardsContent from '../../../../components/list_cards/CyioListCardsContent';
import { RiskCard, RiskCardDummy } from './RiskCard';
import { setNumberOfElements } from '../../../../utils/Number';
import StixDomainObjectBookmarks, {
  stixDomainObjectBookmarksQuery,
} from '../../common/stix_domain_objects/StixDomainObjectBookmarks';
import { QueryRenderer } from '../../../../relay/environment';

const nbOfCardsToLoad = 50;

class RisksCards extends Component {
  constructor(props) {
    super(props);
    this.state = { bookmarks: [] };
  }

  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'poamItems',
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
    //   variables={{ types: ['Device'] }}
    //   render={({ props }) => (
    //     <div>
    //       <StixDomainObjectBookmarks
    //         data={props}
    //         onLabelClick={onLabelClick.bind(this)}
    //         setBookmarkList={this.handleSetBookmarkList.bind(this)}
    //       />
            <CyioListCardsContent
              initialLoading={initialLoading}
              loadMore={relay.loadMore.bind(this)}
              hasMore={relay.hasMore.bind(this)}
              isLoading={relay.isLoading.bind(this)}
              dataList={pathOr([], ['poamItems', 'edges'], this.props.data)}
              globalCount={pathOr(
                nbOfCardsToLoad,
                ['poamItems', 'pageInfo', 'globalCount'],
                this.props.data,
              )}
              CardComponent={<RiskCard />}
              DummyCardComponent={<RiskCardDummy />}
              nbOfCardsToLoad={nbOfCardsToLoad}
              selectAll={selectAll}
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

RisksCards.propTypes = {
  data: PropTypes.object,
  extra: PropTypes.object,
  connectorsExport: PropTypes.array,
  relay: PropTypes.object,
  initialLoading: PropTypes.bool,
  onLabelClick: PropTypes.func,
  setNumberOfElements: PropTypes.func,
};

export const risksCardsQuery = graphql`
  query RisksCardsPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderedBy: POAMItemsOrdering
    $orderMode: OrderingMode
    $filters: [POAMItemsFiltering]
  ) {
    ...RisksCards_data
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
  RisksCards,
  {
    data: graphql`
      fragment RisksCards_data on Query
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
              ...RiskCard_node
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
    query: risksCardsQuery,
  },
);
