import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import { graphql } from 'react-relay';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import User, { userQuery } from './User';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';

const subscription = graphql`
  subscription RootUsersSubscription($id: ID!) {
    user(id: $id) {
      ...User_user
      ...UserEdition_user
    }
  }
`;

class RootUser extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { userId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: userId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      match: {
        params: { userId },
      },
    } = this.props;
    return (
      <Security needs={[SETTINGS_SETACCESSES]}>
        <TopBar />
        <QueryRenderer
          query={userQuery}
          variables={{ id: userId }}
          render={({ props }) => {
            if (props) {
              if (props.user) {
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
              return <ErrorNotFound />;
            }
            return <Loader />;
          }}
        />
      </Security>
    );
  }
}

RootUser.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default withRouter(RootUser);
