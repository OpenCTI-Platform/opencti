import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import User from './User';
import Loader from '../../../../components/Loader';

const subscription = graphql`
  subscription RootUsersSubscription($id: ID!) {
    user(id: $id) {
      ...User_user
      ...UserEdition_user
    }
  }
`;

const userQuery = graphql`
  query RootUserQuery($id: String!) {
    user(id: $id) {
      id
      name
      ...User_user
    }
  }
`;

class RootUser extends Component {
  componentDidMount() {
    const {
      match: {
        params: { userId },
      },
    } = this.props;
    const sub = requestSubscription({
      subscription,
      variables: { id: userId },
    });
    this.setState({ sub });
  }

  componentWillUnmount() {
    this.state.sub.dispose();
  }

  render() {
    const {
      me,
      match: {
        params: { userId },
      },
    } = this.props;
    return (
      <div>
        <TopBar me={me || null} />
        <QueryRenderer
          query={userQuery}
          variables={{ id: userId }}
          render={({ props }) => {
            if (props && props.user) {
              return (
                <div>
                  <Route
                    exact
                    path="/dashboard/settings/accesses/users/:userId"
                    render={(routeProps) => (
                      <User {...routeProps} user={props.user} />
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

RootUser.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootUser);
