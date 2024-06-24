import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Routes, Link, Navigate } from 'react-router-dom';
import { graphql } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import * as R from 'ramda';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import withRouter from '../../../../utils/compat-router/withRouter';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
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
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';

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
      stixCoreObjectsDistribution(field: "entity_type", operation: count) {
        label
        value
      }
      ...Position_position
      ...PositionKnowledge_position
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...StixCoreObjectContent_stixCoreObject
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
      <>
        <QueryRenderer
          query={positionQuery}
          variables={{ id: positionId }}
          render={({ props }) => {
            if (props) {
              if (props.position) {
                const { position } = props;
                const paddingRight = getPaddingRight(location.pathname, position.id, '/dashboard/locations/positions');
                return (
                  <>
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
                            stixCoreObjectsDistribution={position.stixCoreObjectsDistribution}
                          />
                        }
                      />
                    </Routes>
                    <div style={{ paddingRight }}>
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
                        PopoverComponent={<PositionPopover />}
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
                          value={getCurrentTab(location.pathname, position.id, '/dashboard/locations/positions')}
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
                            to={`/dashboard/locations/positions/${position.id}/content`}
                            value={`/dashboard/locations/positions/${position.id}/content`}
                            label={t('Content')}
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
                            <Navigate to={`/dashboard/locations/positions/${positionId}/knowledge/overview`} replace={true} />
                        }
                        />
                        <Route
                          path="/knowledge/*"
                          element={
                            <PositionKnowledge position={props.position} />
                        }
                        />
                        <Route
                          path="/content/*"
                          element={
                            <StixCoreObjectContentRoot
                              stixCoreObject={position}
                            />
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
                  </>
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
