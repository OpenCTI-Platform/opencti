/* eslint-disable no-underscore-dangle,no-nested-ternary */
// TODO Remove no-nested-ternary
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import {
  defaultTo,
  filter,
  lensProp,
  map,
  over,
  pathOr,
  pipe,
  propOr,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import {
  AutoSizer,
  InfiniteLoader,
  List,
  WindowScroller,
} from 'react-virtualized';
import { UserLine, UserLineDummy } from './UserLine';

const styles = () => ({
  windowScrollerWrapper: {
    flex: '1 1 auto',
  },
  item: {
    paddingLeft: 10,
    textTransform: 'uppercase',
    cursor: 'pointer',
  },
  title: {
    float: 'left',
  },
  search: {
    float: 'right',
    marginTop: '-10px',
  },
});

class UsersLines extends Component {
  constructor(props) {
    super(props);
    this._isRowLoaded = this._isRowLoaded.bind(this);
    this._loadMore = this._loadMore.bind(this);
    this._rowRenderer = this._rowRenderer.bind(this);
    this._setRef = this._setRef.bind(this);
    this.state = {
      scrollToIndex: -1,
      showHeaderText: true,
    };
  }

  componentDidUpdate(prevProps) {
    if (this.props.searchTerm !== prevProps.searchTerm) {
      this._loadMore();
    }
  }

  filterList(list) {
    const searchTerm = propOr('', 'searchTerm', this.props);
    const filterByKeyword = n => searchTerm === ''
      || n.node.name.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1
      || n.node.description.toLowerCase().indexOf(searchTerm.toLowerCase())
        !== -1
      || n.node.firstname.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1
      || n.node.lastname.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1
      || n.node.email.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1;
    if (searchTerm.length > 0) {
      return pipe(
        map(n => n.node),
        map(n => over(lensProp('firstname'), defaultTo('-'))(n)),
        map(n => over(lensProp('lastname'), defaultTo('-'))(n)),
        map(n => over(lensProp('description'), defaultTo('-'))(n)),
        map(n => over(lensProp('email'), defaultTo('-'))(n)),
        map(n => ({ node: n })),
        filter(filterByKeyword),
      )(list);
    }
    return list;
  }

  _setRef(windowScroller) {
    // noinspection JSUnusedGlobalSymbols
    this._windowScroller = windowScroller;
  }

  _loadMore() {
    if (!this.props.relay.hasMore() || this.props.relay.isLoading()) {
      return;
    }
    this.props.relay.loadMore(
      this.props.searchTerm.length > 0 ? 100000 : 25,
    );
  }

  _isRowLoaded({ index }) {
    if (this.props.dummy) {
      return true;
    }
    const list = this.filterList(
      pathOr([], ['users', 'edges'], this.props.data),
    );
    return !this.props.relay.hasMore() || index < list.length;
  }

  _rowRenderer({ index, key, style }) {
    const { dummy } = this.props;
    if (dummy) {
      return (
        <div key={key} style={style}>
          <UserLineDummy />
        </div>
      );
    }

    const list = this.filterList(
      pathOr([], ['users', 'edges'], this.props.data),
    );
    if (!this._isRowLoaded({ index })) {
      return (
        <div key={key} style={style}>
          <UserLineDummy />
        </div>
      );
    }
    const userNode = list[index];
    if (!userNode) {
      return <div key={key}>&nbsp;</div>;
    }
    const user = userNode.node;
    return (
      <div key={key} style={style}>
        <UserLine
          key={user.id}
          user={user}
          paginationOptions={this.props.paginationOptions}
        />
      </div>
    );
  }

  render() {
    const { dummy } = this.props;
    const { scrollToIndex } = this.state;
    const list = dummy
      ? []
      : this.filterList(pathOr([], ['users', 'edges'], this.props.data));
    const rowCount = dummy
      ? 20
      : this.props.relay.isLoading()
        ? list.length + 25
        : list.length;
    return (
      <WindowScroller ref={this._setRef} scrollElement={window}>
        {({
          height, isScrolling, onChildScroll, scrollTop,
        }) => (
          <div className={styles.windowScrollerWrapper}>
            <InfiniteLoader
              isRowLoaded={this._isRowLoaded}
              loadMoreRows={this._loadMore}
              rowCount={Number.MAX_SAFE_INTEGER}
            >
              {({ onRowsRendered }) => (
                <AutoSizer disableHeight>
                  {({ width }) => (
                    <List
                      ref={(el) => {
                        window.listEl = el;
                      }}
                      autoHeight
                      height={height}
                      onRowsRendered={onRowsRendered}
                      isScrolling={isScrolling}
                      onScroll={onChildScroll}
                      overscanRowCount={2}
                      rowCount={rowCount}
                      rowHeight={50}
                      rowRenderer={this._rowRenderer}
                      scrollToIndex={scrollToIndex}
                      scrollTop={scrollTop}
                      width={width}
                    />
                  )}
                </AutoSizer>
              )}
            </InfiniteLoader>
          </div>
        )}
      </WindowScroller>
    );
  }
}

UsersLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  data: PropTypes.object,
  relay: PropTypes.object,
  users: PropTypes.object,
  dummy: PropTypes.bool,
  searchTerm: PropTypes.string,
};

export const usersLinesQuery = graphql`
  query UsersLinesPaginationQuery(
    $count: Int!
    $cursor: ID
    $orderBy: UsersOrdering
    $orderMode: OrderingMode
    $isUser: Boolean
  ) {
    ...UsersLines_data
      @arguments(
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
        isUser: $isUser
      )
  }
`;

export const usersLinesSearchQuery = graphql`
  query UsersLinesSearchQuery($search: String) {
    users(search: $search) {
      edges {
        node {
          id
          name
          email
          firstname
          lastname
          created_at
        }
      }
    }
  }
`;

export default withStyles(styles)(
  createPaginationContainer(
    UsersLines,
    {
      data: graphql`
        fragment UsersLines_data on Query
          @argumentDefinitions(
            count: { type: "Int", defaultValue: 25 }
            cursor: { type: "ID" }
            orderBy: { type: "UsersOrdering", defaultValue: ID }
            orderMode: { type: "OrderingMode", defaultValue: "asc" }
            isUser: { type: "Boolean" }
          ) {
          users(
            first: $count
            after: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
            isUser: $isUser
          ) @connection(key: "Pagination_users") {
            edges {
              node {
                id
                name
                firstname
                lastname
                email
                ...UserLine_user
              }
            }
          }
        }
      `,
    },
    {
      direction: 'forward',
      getConnectionFromProps(props) {
        return props.data && props.data.users;
      },
      getFragmentVariables(prevVars, totalCount) {
        return {
          ...prevVars,
          count: totalCount,
        };
      },
      getVariables(props, { count, cursor }, fragmentVariables) {
        return {
          count,
          cursor,
          orderBy: fragmentVariables.orderBy,
          orderMode: fragmentVariables.orderMode,
          isUser: fragmentVariables.isUser,
        };
      },
      query: usersLinesQuery,
    },
  ),
);
