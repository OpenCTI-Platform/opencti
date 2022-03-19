import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import { graphql } from 'react-relay';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import StixCyberObservable from './StixCyberObservable';
import StixCyberObservableKnowledge from './StixCyberObservableKnowledge';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCyberObservableHeader from './StixCyberObservableHeader';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import FileManager from '../../common/files/FileManager';

const subscription = graphql`
  subscription RootStixCyberObservableSubscription($id: ID!) {
    stixCyberObservable(id: $id) {
      ...StixCyberObservable_stixCyberObservable
      ...StixCyberObservableEditionContainer_stixCyberObservable
      ...StixCyberObservableKnowledge_stixCyberObservable
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...FilePendingViewer_entity
    }
  }
`;

const stixCyberObservableQuery = graphql`
  query RootStixCyberObservableQuery($id: String!) {
    stixCyberObservable(id: $id) {
      id
      standard_id
      ...StixCyberObservable_stixCyberObservable
      ...StixCyberObservableHeader_stixCyberObservable
      ...StixCyberObservableDetails_stixCyberObservable
      ...StixCyberObservableIndicators_stixCyberObservable
      ...StixCyberObservableKnowledge_stixCyberObservable
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...FilePendingViewer_entity
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
  }
`;

class RootStixCyberObservable extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { observableId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: observableId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      me,
      match: {
        params: { observableId },
      },
    } = this.props;
    const link = `/dashboard/observations/observables/${observableId}/knowledge`;
    return (
      <div>
        <TopBar me={me || null} />
        <QueryRenderer
          query={stixCyberObservableQuery}
          variables={{ id: observableId, relationship_type: 'indicates' }}
          render={({ props }) => {
            if (props) {
              if (props.stixCyberObservable) {
                return (
                  <div>
                    <Route
                      exact
                      path="/dashboard/observations/observables/:observableId"
                      render={(routeProps) => (
                        <StixCyberObservable
                          {...routeProps}
                          stixCyberObservable={props.stixCyberObservable}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/observations/observables/:observableId/knowledge"
                      render={(routeProps) => (
                        <StixCyberObservableKnowledge
                          {...routeProps}
                          stixCyberObservable={props.stixCyberObservable}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/observations/observables/:observableId/containers"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixCyberObservableHeader
                            stixCyberObservable={props.stixCyberObservable}
                          />
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            {...routeProps}
                            stixDomainObjectOrStixCoreRelationship={
                              props.stixCyberObservable
                            }
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/observations/observables/:observableId/sightings"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixCyberObservableHeader
                            stixCyberObservable={props.stixCyberObservable}
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
                              'System',
                            ]}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/observations/observables/:observableId/files"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixCyberObservableHeader
                            stixCyberObservable={props.stixCyberObservable}
                          />
                          <FileManager
                            {...routeProps}
                            id={observableId}
                            connectorsImport={[]}
                            connectorsExport={props.connectorsForExport}
                            entity={props.stixCyberObservable}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/observations/observables/:observableId/history"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixCyberObservableHeader
                            stixCyberObservable={props.stixCyberObservable}
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
                      path="/dashboard/observations/observables/:observableId/knowledge/relations/:relationId"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixCyberObservableHeader
                            stixCyberObservable={props.stixCyberObservable}
                          />
                          <StixCoreRelationship
                            entityId={observableId}
                            {...routeProps}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/observations/observables/:observableId/knowledge/sightings/:sightingId"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixCyberObservableHeader
                            stixCyberObservable={props.stixCyberObservable}
                          />
                          <StixSightingRelationship
                            entityId={observableId}
                            {...routeProps}
                          />
                        </React.Fragment>
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

RootStixCyberObservable.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootStixCyberObservable);
