import React, { Component } from 'react';
import { QueryRenderer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import environment from '../../../relay/environment';
import Vulnerabilities from './Vulnerabilities';

export const VulnerabilitiesPaginationQuery = graphql`
    query TestPaginationQuery($count: Int!, $cursor: ID, $orderBy: UsersOrdering) {
        ...Vulnerabilities_data @arguments(count: $count, cursor: $cursor, orderBy: $orderBy)
    }
`;

class Test extends Component {
  // eslint-disable-next-line class-methods-use-this
  render() {
    return (
      <QueryRenderer
        environment={environment}
        query={VulnerabilitiesPaginationQuery}
        variables={{ count: 2, orderBy: 'ID' }}
        render={({ error, props }) => {
          if (error) {
            return <div>{error.message}</div>;
          } if (props) {
            return <Vulnerabilities data={props}/>;
          }
          return <div>Loading</div>;
        }}
      />
    );
  }
}

export default Test;
