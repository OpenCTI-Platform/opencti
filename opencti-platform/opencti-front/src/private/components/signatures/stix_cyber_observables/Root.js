import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import StixCyberObservable from './StixCyberObservable';
import StixCyberObservableLinks from './StixCyberObservableLinks';
import StixCyberObservableKnowledge from './StixCyberObservableKnowledge';
import Loader from '../../../../components/Loader';
import StixObjectHistory from '../../common/stix_object/StixObjectHistory';
import StixCyberObservableHeader from './StixCyberObservableHeader';
import EntityStixSightingRelationships from '../../common/stix_sighting_relationships/EntityStixSightingRelationships';

const subscription = graphql`
  subscription RootStixCyberObservableSubscription($id: ID!) {
    stixCyberObservable(id: $id) {
      ...StixCyberObservable_stixCyberObservable
      ...StixCyberObservableEditionContainer_stixCyberObservable
      ...StixCyberObservableKnowledge_stixCyberObservable
      ...StixCyberObservableLinks_stixCyberObservable
    }
  }
`;

const stixCyberObservableQuery = graphql`
  query RootStixCyberObservableQuery($id: String!) {
    stixCyberObservable(id: $id) {
      ...StixCyberObservable_stixCyberObservable
      ...StixCyberObservableHeader_stixCyberObservable
      ...StixCyberObservableOverview_stixCyberObservable
      ...StixCyberObservableDetails_stixCyberObservable
      ...StixCyberObservableIndicators_stixCyberObservable
      ...StixCyberObservableKnowledge_stixCyberObservable
      ...StixCyberObservableLinks_stixCyberObservable
    }
  }
`;

class RootStixCyberObservable extends Component {
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
          query={stixCyberObservableQuery}
          variables={{ id: observableId, relationType: 'indicates' }}
          render={({ props }) => {
            if (props && props.stixCyberObservable) {
              return (
                <div>
                  <Route
                    exact
                    path="/dashboard/signatures/observables/:observableId"
                    render={(routeProps) => (
                      <StixCyberObservable
                        {...routeProps}
                        stixCyberObservable={props.stixCyberObservable}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/signatures/observables/:observableId/links"
                    render={(routeProps) => (
                      <StixCyberObservableLinks
                        {...routeProps}
                        stixCyberObservable={props.stixCyberObservable}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/signatures/observables/:observableId/knowledge"
                    render={(routeProps) => (
                      <StixCyberObservableKnowledge
                        {...routeProps}
                        stixCyberObservable={props.stixCyberObservable}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/signatures/observables/:observableId/sightings"
                    render={(routeProps) => (
                      <React.Fragment>
                        <StixCyberObservableHeader
                          stixCyberObservable={props.stixCyberObservable}
                        />
                        <EntityStixSightingRelationships
                          {...routeProps}
                          entityId={observableId}
                          targetEntityTypes={[
                            'Region',
                            'Country',
                            'City',
                            'Organization',
                            'User',
                          ]}
                        />
                      </React.Fragment>
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/signatures/observables/:observableId/history"
                    render={(routeProps) => (
                      <React.Fragment>
                        <StixCyberObservableHeader
                          stixCyberObservable={props.stixCyberObservable}
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
                      <StixCoreRelationship
                        entityId={observableId}
                        {...routeProps}
                      />
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

RootStixCyberObservable.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootStixCyberObservable);
