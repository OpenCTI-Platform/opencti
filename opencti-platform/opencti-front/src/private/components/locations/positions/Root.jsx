import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter, Switch, Link } from 'react-router-dom';
import { graphql } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import * as R from 'ramda';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
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
import inject18n from '../../../../components/i18n';

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
      entity_type
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
      t,
      location,
      match: {
        params: { positionId },
      },
    } = this.props;
    const link = `/dashboard/locations/positions/${positionId}/knowledge`;
    return (
      <>
        <Route path="/dashboard/locations/positions/:positionId/knowledge">
          <StixCoreObjectKnowledgeBar
            stixCoreObjectLink={link}
            availableSections={[
              'organizations',
              'regions',
              'countries',
              'areas',
              'cities',
              'locations',
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
                const { position } = props;
                return (
                  <div
                    style={{
                      paddingRight: location.pathname.includes(
                        `/dashboard/locations/positions/${position.id}/knowledge`,
                      )
                        ? 200
                        : 0,
                    }}
                  >
                    <StixDomainObjectHeader
                      entityType="Position"
                      disableSharing={true}
                      stixDomainObject={props.position}
                      PopoverComponent={<PositionPopover />}
                    />
                    <Box
                      sx={{
                        borderBottom: 1,
                        borderColor: 'divider',
                        marginBottom: 4,
                      }}
                    >
                      <Tabs
                        value={
                          location.pathname.includes(
                            `/dashboard/locations/positions/${position.id}/knowledge`,
                          )
                            ? `/dashboard/locations/positions/${position.id}/knowledge`
                            : location.pathname
                        }
                      >
                        <Tab
                          component={Link}
                          to={`/dashboard/locations/positions/${position.id}`}
                          value={`/dashboard/locations/positions/${position.id}`}
                          label={t('Overview')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/locations/positions/${position.id}/knowledge`}
                          value={`/dashboard/locations/positions/${position.id}/knowledge`}
                          label={t('Knowledge')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/locations/positions/${position.id}/analyses`}
                          value={`/dashboard/locations/positions/${position.id}/analyses`}
                          label={t('Analyses')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/locations/positions/${position.id}/files`}
                          value={`/dashboard/locations/positions/${position.id}/files`}
                          label={t('Data')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/locations/positions/${position.id}/history`}
                          value={`/dashboard/locations/positions/${position.id}/history`}
                          label={t('History')}
                        />
                      </Tabs>
                    </Box>
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
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            {...routeProps}
                            stixDomainObjectOrStixCoreRelationship={
                              props.position
                            }
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/locations/positions/:positionId/sightings"
                        render={(routeProps) => (
                          <EntityStixSightingRelationships
                            entityId={props.position.id}
                            entityLink={link}
                            noPadding={true}
                            isTo={true}
                            {...routeProps}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/locations/positions/:positionId/files"
                        render={(routeProps) => (
                          <FileManager
                            {...routeProps}
                            id={positionId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={props.position}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/locations/positions/:positionId/history"
                        render={(routeProps) => (
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={positionId}
                          />
                        )}
                      />
                    </Switch>
                  </div>
                );
              }
              return <ErrorNotFound />;
            }
            return <Loader />;
          }}
        />
      </>
    );
  }
}

RootPosition.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootPosition);
