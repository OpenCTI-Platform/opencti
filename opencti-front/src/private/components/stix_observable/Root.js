import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import { QueryRenderer, requestSubscription } from '../../../relay/environment';
import TopBar from '../nav/TopBar';
import StixObservable from './StixObservable';

const subscription = graphql`
  subscription RootStixObservableSubscription($id: ID!) {
    stixObservable(id: $id) {
      ...StixObservable_stixObservable
      ...StixObservableEditionContainer_stixObservable
    }
  }
`;

const stixObservableQuery = graphql`
  query RootStixObservableQuery($id: String!) {
    stixObservable(id: $id) {
      ...StixObservable_stixObservable
      ...StixObservableHeader_stixObservable
      ...StixObservableOverview_stixObservable
    }
  }
`;

class RootStixObservable extends Component {
  componentDidMount() {
    const {
      match: {
        params: { stixObservableId },
      },
    } = this.props;
    const sub = requestSubscription({
      subscription,
      variables: { id: stixObservableId },
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
        params: { observableId },
      },
    } = this.props;
    return (
      <div>
        <TopBar me={me || null} />
        <QueryRenderer
          query={stixObservableQuery}
          variables={{ id: observableId }}
          render={({ props }) => {
            if (props && props.stixObservable) {
              return (
                <div>
                  <Route
                    exact
                    path="/dashboard/observables/all/:observableId"
                    render={routeProps => (
                      <StixObservable
                        {...routeProps}
                        stixObservable={props.stixObservable}
                      />
                    )}
                  />
                </div>
              );
            }
            return <div> &nbsp; </div>;
          }}
        />
      </div>
    );
  }
}

RootStixObservable.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootStixObservable);
