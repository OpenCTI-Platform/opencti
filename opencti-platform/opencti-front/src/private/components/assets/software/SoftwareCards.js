import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListCardsContent from '../../../../components/list_cards/ListCardsContent';
import { SoftwareCardDummy, SoftwareCard } from './SoftwareCard';
import { setNumberOfElements } from '../../../../utils/Number';
import { QueryRenderer } from '../../../../relay/environment';
import StixDomainObjectBookmarks, {
  stixDomainObjectBookmarksQuery,
} from '../../common/stix_domain_objects/StixDomainObjectBookmarks';

const nbOfCardsToLoad = 50;

class SoftwareCards extends Component {
  constructor(props) {
    super(props);
    this.state = { bookmarks: [] };
  }

  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'software',
      this.props.setNumberOfElements.bind(this),
    );
  }

  handleSetBookmarkList(bookmarks) {
    this.setState({ bookmarks });
  }

  render() {
    const { initialLoading, relay, onLabelClick } = this.props;
    const { bookmarks } = this.state;
    return (
      <QueryRenderer
        query={stixDomainObjectBookmarksQuery}
        variables={{ types: ['Software'] }}
        render={({ props }) => (
          <div>
            <StixDomainObjectBookmarks
              data={props}
              onLabelClick={onLabelClick.bind(this)}
              setBookmarkList={this.handleSetBookmarkList.bind(this)}
            />
            <ListCardsContent
              initialLoading={initialLoading}
              loadMore={relay.loadMore.bind(this)}
              hasMore={relay.hasMore.bind(this)}
              isLoading={relay.isLoading.bind(this)}
              dataList={pathOr([], ['software', 'edges'], this.props.data)}
              globalCount={pathOr(
                nbOfCardsToLoad,
                ['software', 'pageInfo', 'globalCount'],
                this.props.data,
              )}
              CardComponent={<SoftwareCard />}
              DummyCardComponent={<SoftwareCardDummy />}
              nbOfCardsToLoad={nbOfCardsToLoad}
              onLabelClick={onLabelClick.bind(this)}
              bookmarkList={bookmarks}
            />
          </div>
        )}
      />
    );
  }
}

SoftwareCards.propTypes = {
  data: PropTypes.object,
  relay: PropTypes.object,
  initialLoading: PropTypes.bool,
  onLabelClick: PropTypes.func,
  setNumberOfElements: PropTypes.func,
};

export const softwareCardsQuery = graphql`
  query SoftwareCardsPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: CampaignsOrdering
    $orderMode: OrderingMode
    $filters: [CampaignsFiltering]
  ) {
    ...SoftwareCards_data
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

export default createPaginationContainer(
  SoftwareCards,
  {
    data: graphql`
      fragment SoftwareCards_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "CampaignsOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "[CampaignsFiltering]" }
      ) {
        campaigns(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) @connection(key: "Pagination_campaigns") {
          edges {
            node {
              id
              name
              description
              ...SoftwareCard_node
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
      return props.data && props.data.software;
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
    query: softwareCardsQuery,
  },
);
