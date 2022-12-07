/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import CyioListCardsContent from '../../../../../components/list_cards/CyioListCardsContent';
import { DataSourceCard, DataSourceCardDummy } from './DataSourceCard';
import { setNumberOfElements } from '../../../../../utils/Number';
import StixDomainObjectBookmarks, {
  stixDomainObjectBookmarksQuery,
} from '../../../common/stix_domain_objects/StixDomainObjectBookmarks';
import { QueryRenderer } from '../../../../../relay/environment';

const nbOfCardsToLoad = 50;

class DataSourcesCards extends Component {
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
      'dataSources',
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
      history,
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
        dataList={pathOr([], ['dataSources', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfCardsToLoad,
          ['dataSources', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        offset={offset}
        CardComponent={<DataSourceCard history={history} />}
        DummyCardComponent={<DataSourceCardDummy />}
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

DataSourcesCards.propTypes = {
  data: PropTypes.object,
  extra: PropTypes.object,
  history: PropTypes.object,
  connectorsExport: PropTypes.array,
  relay: PropTypes.object,
  initialLoading: PropTypes.bool,
  onLabelClick: PropTypes.func,
  setNumberOfElements: PropTypes.func,
};

export const dataSourcesCardsQuery = graphql`
  query DataSourcesCardsPaginationQuery(
    $search: String
    $first: Int!
    $offset: Int!
    $cursor: ID
    $orderedBy: DataSourceOrdering
    $orderMode: OrderingMode
    $filters: [DataSourceFiltering]
    $filterMode: FilterMode
  ) {
    ...DataSourcesCards_data
      @arguments(
        search: $search
        first: $first
        offset: $offset
        cursor: $cursor
        orderedBy: $orderedBy
        orderMode: $orderMode
        filters: $filters
        filterMode: $filterMode
      )
  }
`;

export default createPaginationContainer(
  DataSourcesCards,
  {
    data: graphql`
      fragment DataSourcesCards_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        first: { type: "Int", defaultValue: 50 }
        offset: { type: "Int", defaultValue: 0 }
        cursor: { type: "ID" }
        orderedBy: { type: "DataSourceOrdering", defaultValue: created }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "[DataSourceFiltering]" }
        filterMode: { type: "FilterMode" }
      ) {
        dataSources(
          search: $search
          first: $first
          offset: $offset
          orderedBy: $orderedBy
          orderMode: $orderMode
          filters: $filters
          filterMode: $filterMode
        ) @connection(key: "Pagination_dataSources") {
          edges {
            node {
              id
              name
              description
              ...DataSourceCard_node
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
      return props.data && props.data.dataSources;
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
        orderedBy: fragmentVariables.orderedBy,
        orderMode: fragmentVariables.orderMode,
        filters: fragmentVariables.filters,
        filterMode: fragmentVariables.filterMode,
      };
    },
    query: dataSourcesCardsQuery,
  },
);
