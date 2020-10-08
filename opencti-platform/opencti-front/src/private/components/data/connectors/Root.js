import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import { QueryRenderer } from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import Connector from './Connector';
import Loader from '../../../../components/Loader';

const connectorQuery = graphql`
  query RootConnectorQuery($id: String!) {
    connector(id: $id) {
      id
      name
      ...Connector_connector
    }
  }
`;

class RootConnector extends Component {
  render() {
    const {
      me,
      match: {
        params: { connectorId },
      },
    } = this.props;
    return (
      <div>
        <TopBar me={me || null} />
        <QueryRenderer
          query={connectorQuery}
          variables={{ id: connectorId }}
          render={({ props }) => {
            if (props && props.connector) {
              return (
                <div>
                  <Route
                    exact
                    path="/dashboard/data/connectors/:connectorId"
                    render={(routeProps) => (
                      <Connector {...routeProps} connector={props.connector} />
                    )}
                  />
                </div>
              );
            }
            return <Loader />;
          }}
        />
      </div>
    );
  }
}

RootConnector.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootConnector);
