import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Routes, Link } from 'react-router-dom';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import withRouter from '../../../../utils/compat-router/withRouter';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import StixCyberObservable from '../stix_cyber_observables/StixCyberObservable';
import StixCyberObservableKnowledge from '../stix_cyber_observables/StixCyberObservableKnowledge';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCyberObservableHeader from '../stix_cyber_observables/StixCyberObservableHeader';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import FileManager from '../../common/files/FileManager';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';
import inject18n from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';

const subscription = graphql`
  subscription RootArtifactSubscription($id: ID!) {
    stixCyberObservable(id: $id) {
      ...StixCyberObservable_stixCyberObservable
      ...StixCyberObservableEditionContainer_stixCyberObservable
      ...StixCyberObservableKnowledge_stixCyberObservable
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const rootArtifactQuery = graphql`
  query RootArtifactQuery($id: String!) {
    stixCyberObservable(id: $id) {
      id
      standard_id
      entity_type
      observable_value
      ...StixCyberObservable_stixCyberObservable
      ...StixCyberObservableHeader_stixCyberObservable
      ...StixCyberObservableDetails_stixCyberObservable
      ...StixCyberObservableIndicators_stixCyberObservable
      ...StixCyberObservableKnowledge_stixCyberObservable
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

class RootArtifact extends Component {
  constructor(props) {
    super(props);
    const {
      params: { observableId },
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
      t,
      location,
      params: { observableId },
    } = this.props;
    const link = `/dashboard/observations/artifacts/${observableId}/knowledge`;
    return (
      <>
        <QueryRenderer
          query={rootArtifactQuery}
          variables={{ id: observableId, relationship_type: 'indicates' }}
          render={({ props }) => {
            if (props) {
              if (props.stixCyberObservable) {
                const { stixCyberObservable } = props;
                const paddingRight = getPaddingRight(location.pathname, stixCyberObservable.id, '/dashboard/observations/artifacts', false);
                return (
                  <div style={{ paddingRight }}>
                    <Breadcrumbs variant="object" elements={[
                      { label: t('Observations') },
                      { label: t('Artifacts'), link: '/dashboard/observations/artifacts' },
                      { label: stixCyberObservable.observable_value, current: true },
                    ]}
                    />
                    <StixCyberObservableHeader
                      stixCyberObservable={stixCyberObservable}
                      isArtifact={true}
                    />
                    <Box
                      sx={{
                        borderBottom: 1,
                        borderColor: 'divider',
                        marginBottom: 4,
                      }}
                    >
                      <Tabs
                        value={getCurrentTab(location.pathname, stixCyberObservable.id, '/dashboard/observations/artifacts')}
                      >
                        <Tab
                          component={Link}
                          to={`/dashboard/observations/artifacts/${stixCyberObservable.id}`}
                          value={`/dashboard/observations/artifacts/${stixCyberObservable.id}`}
                          label={t('Overview')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/observations/artifacts/${stixCyberObservable.id}/knowledge`}
                          value={`/dashboard/observations/artifacts/${stixCyberObservable.id}/knowledge`}
                          label={t('Knowledge')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/observations/artifacts/${stixCyberObservable.id}/content`}
                          value={`/dashboard/observations/artifacts/${stixCyberObservable.id}/content`}
                          label={t('Content')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/observations/artifacts/${stixCyberObservable.id}/analyses`}
                          value={`/dashboard/observations/artifacts/${stixCyberObservable.id}/analyses`}
                          label={t('Analyses')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/observations/artifacts/${stixCyberObservable.id}/sightings`}
                          value={`/dashboard/observations/artifacts/${stixCyberObservable.id}/sightings`}
                          label={t('Sightings')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/observations/artifacts/${stixCyberObservable.id}/files`}
                          value={`/dashboard/observations/artifacts/${stixCyberObservable.id}/files`}
                          label={t('Data')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/observations/artifacts/${stixCyberObservable.id}/history`}
                          value={`/dashboard/observations/artifacts/${stixCyberObservable.id}/history`}
                          label={t('History')}
                        />
                      </Tabs>
                    </Box>
                    <Routes>
                      <Route
                        path="/"
                        element={(
                          <StixCyberObservable
                            stixCyberObservable={stixCyberObservable}
                          />
                                )}
                      />
                      <Route
                        path="/knowledge"
                        element={
                          <StixCyberObservableKnowledge
                            stixCyberObservable={stixCyberObservable}
                            connectorsForImport={props.connectorsForImport}
                          />
                                }
                      />
                      <Route
                        path="/content/*"
                        element={
                          <StixCoreObjectContentRoot
                            stixCoreObject={stixCyberObservable}
                          />
                                }
                      />
                      <Route
                        path="/sightings"
                        element={(
                          <EntityStixSightingRelationships
                            entityId={observableId}
                            entityLink={link}
                            noRightBar={true}
                            noPadding={true}
                            stixCoreObjectTypes={[
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
                                )}
                      />
                      <Route
                        path="/files"
                        element={(
                          <FileManager
                            id={observableId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={props.stixCyberObservable}
                            isArtifact={true}
                            directDownload={true}
                          />
                                )}
                      />
                      <Route
                        path="/history"
                        element={(
                          <StixCoreObjectHistory
                            stixCoreObjectId={observableId}
                          />
                                )}
                      />
                      <Route
                        path="/knowledge/relations/:relationId"
                        element={(
                          <StixCoreRelationship
                            entityId={observableId}
                          />
                                )}
                      />
                      <Route
                        path="/knowledge/sightings/:sightingId"
                        element={(
                          <StixSightingRelationship
                            entityId={observableId}
                            paddingRight
                          />
                                )}
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
      </>
    );
  }
}

RootArtifact.propTypes = {
  children: PropTypes.node,
  params: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootArtifact);
