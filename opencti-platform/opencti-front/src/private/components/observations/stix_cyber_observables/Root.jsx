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
import inject18n from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumps';

const subscription = graphql`
  subscription RootStixCyberObservableSubscription($id: ID!) {
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

const stixCyberObservableQuery = graphql`
  query RootStixCyberObservableQuery($id: String!) {
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
      t,
      location,
      match: {
        params: { observableId },
      },
    } = this.props;
    const link = `/dashboard/observations/observables/${observableId}/knowledge`;
    return (
      <>
        <QueryRenderer
          query={stixCyberObservableQuery}
          variables={{ id: observableId, relationship_type: 'indicates' }}
          render={({ props }) => {
            if (props) {
              if (props.stixCyberObservable) {
                const { stixCyberObservable } = props;
                return (
                  <>
                    <Breadcrumbs variant="object" elements={[
                      { label: t('Observations') },
                      { label: t('Observables'), link: '/dashboard/observations/observables' },
                      { label: stixCyberObservable.observable_value, current: true },
                    ]}
                    />
                    <StixCyberObservableHeader
                      stixCyberObservable={stixCyberObservable}
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
                            `/dashboard/observations/observables/${stixCyberObservable.id}/knowledge`,
                          )
                            ? `/dashboard/observations/observables/${stixCyberObservable.id}/knowledge`
                            : location.pathname
                        }
                      >
                        <Tab
                          component={Link}
                          to={`/dashboard/observations/observables/${stixCyberObservable.id}`}
                          value={`/dashboard/observations/observables/${stixCyberObservable.id}`}
                          label={t('Overview')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/observations/observables/${stixCyberObservable.id}/knowledge`}
                          value={`/dashboard/observations/observables/${stixCyberObservable.id}/knowledge`}
                          label={t('Knowledge')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/observations/observables/${stixCyberObservable.id}/analyses`}
                          value={`/dashboard/observations/observables/${stixCyberObservable.id}/analyses`}
                          label={t('Analyses')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/observations/observables/${stixCyberObservable.id}/sightings`}
                          value={`/dashboard/observations/observables/${stixCyberObservable.id}/sightings`}
                          label={t('Sightings')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/observations/observables/${stixCyberObservable.id}/files`}
                          value={`/dashboard/observations/observables/${stixCyberObservable.id}/files`}
                          label={t('Data')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/observations/observables/${stixCyberObservable.id}/history`}
                          value={`/dashboard/observations/observables/${stixCyberObservable.id}/history`}
                          label={t('History')}
                        />
                      </Tabs>
                    </Box>
                    <Switch>
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
                        path="/dashboard/observations/observables/:observableId/analyses"
                        render={(routeProps) => (
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            {...routeProps}
                            stixDomainObjectOrStixCoreRelationship={
                              props.stixCyberObservable
                            }
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/observations/observables/:observableId/sightings"
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
                        path="/dashboard/observations/observables/:observableId/files"
                        render={(routeProps) => (
                          <FileManager
                            {...routeProps}
                            id={observableId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={props.stixCyberObservable}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/observations/observables/:observableId/history"
                        render={(routeProps) => (
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={observableId}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/observations/observables/:observableId/knowledge/relations/:relationId"
                        render={(routeProps) => (
                          <StixCoreRelationship
                            entityId={observableId}
                            {...routeProps}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/observations/observables/:observableId/knowledge/sightings/:sightingId"
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

RootStixCyberObservable.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootStixCyberObservable);
