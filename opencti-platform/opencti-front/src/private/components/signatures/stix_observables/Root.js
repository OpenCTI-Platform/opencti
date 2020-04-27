import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import StixRelation from '../../common/stix_relations/StixRelation';
import StixObservable from './StixObservable';
import StixObservableLinks from './StixObservableLinks';
import StixObservableKnowledge from './StixObservableKnowledge';
import Loader from '../../../../components/Loader';
import StixObjectHistory from '../../common/stix_object/StixObjectHistory';
import StixObservableHeader from './StixObservableHeader';

const subscription = graphql`
  subscription RootStixObservableSubscription($id: ID!) {
    stixObservable(id: $id) {
      ...StixObservable_stixObservable
      ...StixObservableEditionContainer_stixObservable
      ...StixObservableKnowledge_stixObservable
      ...StixObservableLinks_stixObservable
    }
  }
`;

const stixObservableQuery = graphql`
  query RootStixObservableQuery($id: String!) {
    stixObservable(id: $id) {
      ...StixObservable_stixObservable
      ...StixObservableHeader_stixObservable
      ...StixObservableOverview_stixObservable
      ...StixObservableDetails_stixObservable
      ...StixObservableIndicators_stixObservable
      ...StixObservableKnowledge_stixObservable
      ...StixObservableLinks_stixObservable
    }
  }
`;

class RootStixObservable extends Component {
  componentDidMount() {
    const {
      match: {
        params: { observableId },
      },
    } = this.props;
    const sub = requestSubscription({
      subscription,
      variables: { id: observableId },
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
          variables={{ id: observableId, relationType: 'indicates' }}
          render={({ props }) => {
            if (props && props.stixObservable) {
              return (
                <div>
                  <Route
                    exact
                    path="/dashboard/signatures/observables/:observableId"
                    render={(routeProps) => (
                      <StixObservable
                        {...routeProps}
                        stixObservable={props.stixObservable}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/signatures/observables/:observableId/links"
                    render={(routeProps) => (
                      <StixObservableLinks
                        {...routeProps}
                        stixObservable={props.stixObservable}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/signatures/observables/:observableId/knowledge"
                    render={(routeProps) => (
                      <StixObservableKnowledge
                        {...routeProps}
                        stixObservable={props.stixObservable}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/signatures/observables/:observableId/history"
                    render={(routeProps) => (
                      <React.Fragment>
                        <StixObservableHeader
                          stixObservable={props.stixObservable}
                        />
                        <StixObjectHistory
                          {...routeProps}
                          entityId={observableId}
                        />
                      </React.Fragment>
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/signatures/observables/:observableId/knowledge/relations/:relationId"
                    render={(routeProps) => (
                      <StixRelation entityId={observableId} {...routeProps} />
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

RootStixObservable.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootStixObservable);
