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
import StixCyberObservable from '../stix_cyber_observables/StixCyberObservable';
import StixCyberObservableKnowledge from '../stix_cyber_observables/StixCyberObservableKnowledge';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCyberObservableHeader from '../stix_cyber_observables/StixCyberObservableHeader';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import ErrorNotFound from '../../../../components/ErrorNotFound';

const subscription = graphql`
  subscription RootArtifactSubscription($id: ID!) {
    stixCyberObservable(id: $id) {
      ...StixCyberObservable_stixCyberObservable
      ...StixCyberObservableEditionContainer_stixCyberObservable
      ...StixCyberObservableKnowledge_stixCyberObservable
    }
  }
`;

const rootArtifactQuery = graphql`
  query RootArtifactQuery($id: String!) {
    stixCyberObservable(id: $id) {
      id
      standard_id
      ...StixCyberObservable_stixCyberObservable
      ...StixCyberObservableHeader_stixCyberObservable
      ...StixCyberObservableDetails_stixCyberObservable
      ...StixCyberObservableIndicators_stixCyberObservable
      ...StixCyberObservableKnowledge_stixCyberObservable
    }
    connectorsForImport {
      ...StixCyberObservableKnowledge_connectorsForImport
    }
  }
`;

class RootArtifact extends Component {
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
    const link = `/dashboard/observations/artifacts/${observableId}/knowledge`;
    return (
      <div>
        <TopBar me={me || null} />
        <QueryRenderer
          query={rootArtifactQuery}
          variables={{ id: observableId, relationship_type: 'indicates' }}
          render={({ props }) => {
            if (props) {
              if (props.stixCyberObservable) {
                return (
                  <div>
                    <Route
                      exact
                      path="/dashboard/observations/artifacts/:observableId"
                      render={(routeProps) => (
                        <StixCyberObservable
                          {...routeProps}
                          stixCyberObservable={props.stixCyberObservable}
                          isArtifact={true}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/observations/artifacts/:observableId/knowledge"
                      render={(routeProps) => (
                        <StixCyberObservableKnowledge
                          {...routeProps}
                          stixCyberObservable={props.stixCyberObservable}
                          connectorsForImport={props.connectorsForImport}
                          isArtifact={true}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/observations/artifacts/:observableId/sightings"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixCyberObservableHeader
                            stixCyberObservable={props.stixCyberObservable}
                            isArtifact={true}
                          />
                          <EntityStixSightingRelationships
                            {...routeProps}
                            entityId={observableId}
                            entityLink={link}
                            noRightBar={true}
                            noPadding={true}
                            targetStixDomainObjectTypes={[
                              'Region',
                              'Country',
                              'City',
                              'Position',
                              'Sector',
                              'Organization',
                              'Individual',
                            ]}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/observations/artifacts/:observableId/history"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixCyberObservableHeader
                            stixCyberObservable={props.stixCyberObservable}
                            isArtifact={true}
                          />
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={observableId}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/observations/artifacts/:observableId/knowledge/relations/:relationId"
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
              return <ErrorNotFound />;
            }
            return <Loader />;
          }}
        />
      </div>
    );
  }
}

RootArtifact.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootArtifact);
