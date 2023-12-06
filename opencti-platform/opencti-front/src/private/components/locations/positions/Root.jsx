import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Routes, Link, Navigate } from 'react-router-dom';
import { graphql } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import * as R from 'ramda';
import withRouter from '../../../../utils/compat-router/withRouter';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
import Position from './Position';
import PositionKnowledge from './PositionKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import inject18n from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import PositionEdition from './PositionEdition';
import CreateRelationshipButtonComponent from '../../common/menus/RelateComponent';
import RelateComponentContextProvider from '../../common/menus/RelateComponentProvider';

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
      created_at
      updated_at
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
      params: { positionId },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: positionId },
    });
    this.state = {
      reversed: false,
    };
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      t,
      location,
      params: { positionId },
    } = this.props;
    const link = `/dashboard/locations/positions/${positionId}/knowledge`;
    return (
      <RelateComponentContextProvider>
        <Routes>
          <Route
            path="/knowledge/*"
            element={
              <StixCoreObjectKnowledgeBar
                stixCoreObjectLink={link}
                availableSections={[
                  'organizations',
                  'regions',
                  'countries',
                  'areas',
                  'cities',
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
            }
          />
        </Routes>
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
                    <Breadcrumbs variant="object" elements={[
                      { label: t('Locations') },
                      { label: t('Positions'), link: '/dashboard/locations/positions' },
                      { label: position.name, current: true },
                    ]}
                    />
                    <StixDomainObjectHeader
                      entityType="Position"
                      disableSharing={true}
                      stixDomainObject={props.position}
                      EditComponent={<Security needs={[KNOWLEDGE_KNUPDATE]}>
                        <PositionEdition positionId={position.id} />
                      </Security>}
                      RelateComponent={<CreateRelationshipButtonComponent
                        id={position.id}
                        defaultStartTime={position.created_at}
                        defaultStopTime={position.updated_at}
                                       />}
                      enableQuickSubscription={true}
                      isOpenctiAlias={true}
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
                          to={`/dashboard/locations/positions/${position.id}/knowledge/overview`}
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
                          to={`/dashboard/locations/positions/${position.id}/sightings`}
                          value={`/dashboard/locations/positions/${position.id}/sightings`}
                          label={t('Sightings')}
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
                    <Routes>
                      <Route
                        path="/"
                        element={
                          <Position position={props.position} />
                        }
                      />
                      <Route
                        path="/knowledge"
                        element={
                          <Navigate to={`/dashboard/locations/positions/${positionId}/knowledge/overview`} />
                        }
                      />
                      <Route
                        path="/knowledge/*"
                        element={
                          <PositionKnowledge position={props.position} />
                        }
                      />
                      <Route
                        path="/analyses"
                        element={
                          <StixCoreObjectOrStixCoreRelationshipContainers stixDomainObjectOrStixCoreRelationship={props.position} />
                        }
                      />
                      <Route
                        path="/sightings"
                        element={
                          <EntityStixSightingRelationships
                            entityId={props.position.id}
                            entityLink={link}
                            noPadding={true}
                            isTo={true}
                          />
                        }
                      />
                      <Route
                        path="/files"
                        element={
                          <FileManager
                            id={positionId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={props.position}
                          />
                        }
                      />
                      <Route
                        path="/history"
                        element={
                          <StixCoreObjectHistory stixCoreObjectId={positionId} />
                        }
                      />
                    </Routes>
                  </div>
                );
              }
              return <ErrorNotFound />;
            }
            return <Loader />;
          }}
        />
      </RelateComponentContextProvider>
    );
  }
}

RootPosition.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootPosition);
