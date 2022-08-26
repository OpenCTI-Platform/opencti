/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import CyioListCardsContent from '../../../../../components/list_cards/CyioListCardsContent';
import { EntityLabelCard, EntityLabelCardDummy } from './EntityLabelCard';
import { setNumberOfElements } from '../../../../../utils/Number';
import StixDomainObjectBookmarks, {
  stixDomainObjectBookmarksQuery,
} from '../../../common/stix_domain_objects/StixDomainObjectBookmarks';
import { QueryRenderer } from '../../../../../relay/environment';

const nbOfCardsToLoad = 50;

class EntitiesLabelsCards extends Component {
  constructor(props) {
    super(props);
    this.state = {
      bookmarks: [],
      offset: 0,
    };
  }

  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'cyioLabels',
      this.props.setNumberOfElements.bind(this),
    );
  }

  handleSetBookmarkList(bookmarks) {
    this.setState({ bookmarks });
  }

  handleIncrementedOffsetChange() {
    const incrementedOffset = this.state.offset += nbOfCardsToLoad;
    this.setState({ offset: incrementedOffset })
    this.props.relay.refetchConnection(nbOfCardsToLoad, null, {
      offset: this.state.offset,
      first: nbOfCardsToLoad,
       ...this.props.paginationOptions,
    })
  }

  handleDecrementedOffsetChange() {
    const decrementedOffset = this.state.offset -= nbOfCardsToLoad;
    this.setState({ offset: decrementedOffset })
    this.props.relay.refetchConnection(nbOfCardsToLoad, null, {
      offset: this.state.offset,
      first: nbOfCardsToLoad,
       ...this.props.paginationOptions,
    })
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
    const { bookmarks, offset } = this.state;
    return (
      <CyioListCardsContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        handleIncrementedOffsetChange={this.handleIncrementedOffsetChange.bind(this)}
        handleDecrementedOffsetChange={this.handleDecrementedOffsetChange.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['cyioLabels', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfCardsToLoad,
          ['cyioLabels', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        offset={offset}
        CardComponent={<EntityLabelCard />}
        DummyCardComponent={<EntityLabelCardDummy />}
        nbOfCardsToLoad={nbOfCardsToLoad}
        selectAll={selectAll}
        selectedElements={selectedElements}
        onLabelClick={onLabelClick.bind(this)}
        onToggleEntity={onToggleEntity.bind(this)}
        bookmarkList={bookmarks}
      />
    );
  }
}

EntitiesLabelsCards.propTypes = {
  data: PropTypes.object,
  extra: PropTypes.object,
  connectorsExport: PropTypes.array,
  relay: PropTypes.object,
  initialLoading: PropTypes.bool,
  onLabelClick: PropTypes.func,
  setNumberOfElements: PropTypes.func,
};

export const entitiesLabelsCardsQuery = graphql`
  query EntitiesLabelsCardsPaginationQuery(
    $search: String
    $first: Int!
    $offset: Int!
    $cursor: ID
    $orderBy: CyioLabelsOrdering
    $orderMode: OrderingMode
    $filters: [CyioLabelsFiltering]
    $filterMode: FilterMode
  ) {
    ...EntitiesLabelsCards_data
      @arguments(
        search: $search
        first: $first
        offset: $offset
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
        filters: $filters
        filterMode: $filterMode
      )
  }
`;

export default createPaginationContainer(
  EntitiesLabelsCards,
  {
    data: graphql`
      fragment EntitiesLabelsCards_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        first: { type: "Int", defaultValue: 50 }
        offset: { type: "Int", defaultValue: 0 }
        cursor: { type: "ID" }
        orderBy: { type: "CyioLabelsOrdering", defaultValue: created }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "[CyioLabelsFiltering]" }
        filterMode: { type: "FilterMode" }
      ) {
        cyioLabels(
          search: $search
          first: $first
          offset: $offset
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
          filterMode: $filterMode
        ) @connection(key: "Pagination_cyioLabels") {
          edges {
            node {
              id
              name
              description
              ...EntityLabelCard_node
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
      return props.data && props.data.cyioLabels;
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
        first: fragmentVariables.first,
        offset: fragmentVariables.offset,
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
        filters: fragmentVariables.filters,
        filterMode: fragmentVariables.filterMode,
      };
    },
    query: entitiesLabelsCardsQuery,
  },
);
