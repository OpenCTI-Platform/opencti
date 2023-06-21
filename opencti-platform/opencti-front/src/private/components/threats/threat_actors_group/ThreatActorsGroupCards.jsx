import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { pathOr } from 'ramda';
import ListCardsContent from '../../../../components/list_cards/ListCardsContent';
import { ThreatActorGroupCard, ThreatActorGroupCardDummy } from './ThreatActorGroupCard';
import { setNumberOfElements } from '../../../../utils/Number';
import StixDomainObjectBookmarks, {
  stixDomainObjectBookmarksQuery,
} from '../../common/stix_domain_objects/StixDomainObjectBookmarks';
import { QueryRenderer } from '../../../../relay/environment';

const nbOfCardsToLoad = 12;

class ThreatActorsGroupCards extends Component {
  constructor(props) {
    super(props);
    this.state = { bookmarks: [] };
  }

  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'ThreatActorsGroup',
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
        variables={{ types: ['Threat-Actor-Group'] }}
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
              dataList={pathOr([], ['threatActorsGroup', 'edges'], this.props.data)}
              globalCount={pathOr(
                nbOfCardsToLoad,
                ['threatActorsGroup', 'pageInfo', 'globalCount'],
                this.props.data,
              )}
              CardComponent={<ThreatActorGroupCard />}
              DummyCardComponent={<ThreatActorGroupCardDummy />}
              nbOfCardsToLoad={nbOfCardsToLoad}
              onLabelClick={onLabelClick.bind(this)}
              bookmarkList={bookmarks}
              rowHeight={340}
            />
          </div>
        )}
      />
    );
  }
}

ThreatActorsGroupCards.propTypes = {
  data: PropTypes.object,
  extra: PropTypes.object,
  connectorsExport: PropTypes.array,
  relay: PropTypes.object,
  initialLoading: PropTypes.bool,
  onLabelClick: PropTypes.func,
  setNumberOfElements: PropTypes.func,
};

export const threatActorsGroupCardsQuery = graphql`
  query ThreatActorsGroupCardsPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: ThreatActorsGroupOrdering
    $orderMode: OrderingMode
    $filters: [ThreatActorsGroupFiltering]
  ) {
    ...ThreatActorsGroupCards_data
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
  ThreatActorsGroupCards,
  {
    data: graphql`
      fragment ThreatActorsGroupCards_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "ThreatActorsGroupOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "[ThreatActorsGroupFiltering]" }
      ) {
        threatActorsGroup(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) @connection(key: "Pagination_threatActorsGroup") {
          edges {
            node {
              id
              name
              description
              ...ThreatActorGroupCard_node
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
      return props.data && props.data.threatActorsGroup;
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
    query: threatActorsGroupCardsQuery,
  },
);
