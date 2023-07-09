import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter, Switch } from 'react-router-dom';
import { graphql } from 'react-relay';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import Position from './Position';
import PositionKnowledge from './PositionKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import PositionPopover from './PositionPopover';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';

const subscription = graphql`
  subscription RootPositionsSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Position {
        ...Position_position
        ...PositionEditionContainer_position
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const positionQuery = graphql`
  query RootPositionQuery($id: String!) {
    position(id: $id) {
      id
      name
      x_opencti_aliases
      ...Position_position
      ...PositionKnowledge_position
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
    connectorsForImport {
      ...FileManager_connectorsImport
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
  }
`;

class RootPosition extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { positionId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: positionId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      match: {
        params: { positionId },
      },
    } = this.props;
    const link = `/dashboard/locations/positions/${positionId}/knowledge`;
    return (
      <div>
        <TopBar />
        <Route path="/dashboard/locations/positions/:positionId/knowledge">
          <StixCoreObjectKnowledgeBar
            stixCoreObjectLink={link}
            availableSections={[
              'organizations',
              'regions',
              'countries',
              'areas',
              'cities',
              'threats',
              'threat_actors',
              'intrusion_sets',
              'campaigns',
              'incidents',
              'malwares',
              'attack_patterns',
              'tools',
              'observables',
            ]}
          />
        </Route>
        <QueryRenderer
          query={positionQuery}
          variables={{ id: positionId }}
          render={({ props }) => {
            if (props) {
              if (props.position) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/dashboard/locations/positions/:positionId"
                      render={(routeProps) => (
                        <Position {...routeProps} position={props.position} />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/locations/positions/:positionId/knowledge"
                      render={() => (
                        <Redirect
                          to={`/dashboard/locations/positions/${positionId}/knowledge/overview`}
                        />
                      )}
                    />
                    <Route
                      path="/dashboard/locations/positions/:positionId/knowledge"
                      render={(routeProps) => (
                        <PositionKnowledge
                          {...routeProps}
                          position={props.position}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/locations/positions/:positionId/analyses"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'Position'}
                            disableSharing={true}
                            stixDomainObject={props.position}
                            PopoverComponent={<PositionPopover />}
                          />
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            {...routeProps}
                            stixDomainObjectOrStixCoreRelationship={
                              props.position
                            }
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/locations/positions/:positionId/sightings"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'Position'}
                            disableSharing={true}
                            stixDomainObject={props.position}
                            PopoverComponent={<PositionPopover />}
                          />
                          <EntityStixSightingRelationships
                            entityId={props.position.id}
                            entityLink={link}
                            noPadding={true}
                            isTo={true}
                            {...routeProps}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/locations/positions/:positionId/files"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'Position'}
                            disableSharing={true}
                            stixDomainObject={props.position}
                            PopoverComponent={<PositionPopover />}
                          />
                          <FileManager
                            {...routeProps}
                            id={positionId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={props.position}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/locations/positions/:positionId/history"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'Position'}
                            disableSharing={true}
                            stixDomainObject={props.position}
                            PopoverComponent={<PositionPopover />}
                          />
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={positionId}
                          />
                        </React.Fragment>
                      )}
                    />
                  </Switch>
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

RootPosition.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default withRouter(RootPosition);
