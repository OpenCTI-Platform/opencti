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
import StixCyberObservable from '../stix_cyber_observables/StixCyberObservable';
import StixCyberObservableKnowledge from '../stix_cyber_observables/StixCyberObservableKnowledge';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCyberObservableHeader from '../stix_cyber_observables/StixCyberObservableHeader';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import FileManager from '../../common/files/FileManager';

const subscription = graphql`
  subscription RootArtifactSubscription($id: ID!) {
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

class RootArtifact extends Component {
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
                              'System',
                            ]}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/observations/artifacts/:observableId/files"
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
