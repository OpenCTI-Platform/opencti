import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, withRouter, Switch, Link } from 'react-router-dom';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
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
import Breadcrumbs from '../../../../components/Breadcrumps';

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
      t,
      location,
      match: {
        params: { observableId },
      },
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
                return (
                  <>
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
                        value={
                          location.pathname.includes(
                            `/dashboard/observations/artifacts/${stixCyberObservable.id}/knowledge`,
                          )
                            ? `/dashboard/observations/artifacts/${stixCyberObservable.id}/knowledge`
                            : location.pathname
                        }
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
                    <Switch>
                      <Route
                        exact
                        path="/dashboard/observations/artifacts/:observableId"
                        render={(routeProps) => (
                          <StixCyberObservable
                            {...routeProps}
                            stixCyberObservable={stixCyberObservable}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/observations/artifacts/:observableId/knowledge"
                        render={(routeProps) => (
                          <StixCyberObservableKnowledge
                            {...routeProps}
                            stixCyberObservable={stixCyberObservable}
                            connectorsForImport={props.connectorsForImport}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/observations/artifacts/:observableId/sightings"
                        render={(routeProps) => (
                          <EntityStixSightingRelationships
                            {...routeProps}
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
                        exact
                        path="/dashboard/observations/artifacts/:observableId/files"
                        render={(routeProps) => (
                          <FileManager
                            {...routeProps}
                            id={observableId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={props.stixCyberObservable}
                            isArtifact={true}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/observations/artifacts/:observableId/history"
                        render={(routeProps) => (
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={observableId}
                          />
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
                      <Route
                        exact
                        path="/dashboard/observations/artifacts/:observableId/knowledge/sightings/:sightingId"
                        render={(routeProps) => (
                          <StixSightingRelationship
                            entityId={observableId}
                            {...routeProps}
                          />
                        )}
                      />
                    </Switch>
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

RootArtifact.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootArtifact);
