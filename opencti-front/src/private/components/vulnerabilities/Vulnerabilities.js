import React, { Component } from 'react';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import * as PropTypes from 'prop-types';
import UserInformation from '../user/UserInformation';

class Vulnerabilities extends Component {
  render() {
    return (
      <div>
        {this.props.data.users.edges.map(
          edge => <div key={edge.node.id}><UserInformation me={edge.node}/><br/></div>,
        )}
        <button onClick={() => this.loadMore()} title="Load More">Load more</button>
      </div>
    );
  }

  loadMore() {
    if (!this.props.relay.hasMore() || this.props.relay.isLoading()) {
      return;
    }
    // Fetch the next 10 feed items
    this.props.relay.loadMore(2, () => {
      // console.log(error);
    });
  }
}

Vulnerabilities.propTypes = {
  data: PropTypes.object,
  relay: PropTypes.object,
};

export default createPaginationContainer(
  Vulnerabilities,
  {
    data: graphql`
        fragment Vulnerabilities_data on Query @argumentDefinitions(
            count: {type: "Int", defaultValue: 10}
            cursor: {type: "ID"}
            orderBy: {type: "UsersOrdering", defaultValue: ID}
        ) {
            users(
                first: $count
                after: $cursor
                orderBy: $orderBy # Non-pagination variables
            ) @connection(key: "Pagination_users") {
                edges {
                    node {
                        id
                        ...UserInformation_me
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
      };
    },
    query: graphql`
        query VulnerabilitiesPaginationQuery($count: Int!, $cursor: ID, $orderBy: UsersOrdering) {
            ...Vulnerabilities_data @arguments(count: $count, cursor: $cursor, orderBy: $orderBy)
        }
    `,
  },
);
