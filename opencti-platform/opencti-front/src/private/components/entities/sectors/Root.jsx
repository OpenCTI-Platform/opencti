import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter, Switch } from 'react-router-dom';
import { graphql } from 'react-relay';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import Sector from './Sector';
import SectorKnowledge from './SectorKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import SectorPopover from './SectorPopover';
import FileManager from '../../common/files/FileManager';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';

const subscription = graphql`
  subscription RootSectorSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Sector {
        ...Sector_sector
        ...SectorEditionContainer_sector
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
        ...PictureManagementViewer_entity

    }
  }
`;

const sectorQuery = graphql`
  query RootSectorQuery($id: String!) {
    sector(id: $id) {
      id
      standard_id
      name
      x_opencti_aliases
      x_opencti_graph_data
      ...Sector_sector
      ...SectorKnowledge_sector
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
        ...PictureManagementViewer_entity

    }
    connectorsForImport {
      ...FileManager_connectorsImport
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
  }
`;

class RootSector extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { sectorId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: sectorId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      match: {
        params: { sectorId },
      },
    } = this.props;
    const link = `/dashboard/entities/sectors/${sectorId}/knowledge`;
    return (
      <div>
        <TopBar />
        <Route path="/dashboard/entities/sectors/:sectorId/knowledge">
          <StixCoreObjectKnowledgeBar
            stixCoreObjectLink={link}
            availableSections={[
              'organizations',
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
          query={sectorQuery}
          variables={{ id: sectorId }}
          render={({ props }) => {
            if (props) {
              if (props.sector) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/dashboard/entities/sectors/:sectorId"
                      render={(routeProps) => (
                        <Sector {...routeProps} sector={props.sector} />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/entities/sectors/:sectorId/knowledge"
                      render={() => (
                        <Redirect
                          to={`/dashboard/entities/sectors/${sectorId}/knowledge/overview`}
                        />
                      )}
                    />
                    <Route
                      path="/dashboard/entities/sectors/:sectorId/knowledge"
                      render={(routeProps) => (
                        <SectorKnowledge
                          {...routeProps}
                          sector={props.sector}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/entities/sectors/:sectorId/analyses"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'Sector'}
                            disableSharing={true}
                            stixDomainObject={props.sector}
                            isOpenctiAlias={true}
                            PopoverComponent={<SectorPopover />}
                          />
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            {...routeProps}
                            stixDomainObjectOrStixCoreRelationship={
                              props.sector
                            }
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/entities/sectors/:sectorId/sightings"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'Sector'}
                            disableSharing={true}
                            stixDomainObject={props.sector}
                            isOpenctiAlias={true}
                            PopoverComponent={<SectorPopover />}
                          />
                          <EntityStixSightingRelationships
                            entityId={props.sector.id}
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
                      path="/dashboard/entities/sectors/:sectorId/files"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'Sector'}
                            disableSharing={true}
                            stixDomainObject={props.sector}
                            isOpenctiAlias={true}
                            PopoverComponent={<SectorPopover />}
                          />
                          <FileManager
                            {...routeProps}
                            id={sectorId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={props.sector}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/entities/sectors/:sectorId/history"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'Sector'}
                            disableSharing={true}
                            stixDomainObject={props.sector}
                            isOpenctiAlias={true}
                            PopoverComponent={<SectorPopover />}
                          />
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={sectorId}
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

RootSector.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default withRouter(RootSector);
