import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Routes, Link, Navigate } from 'react-router-dom';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import withRouter from '../../../../utils/compat-router/withRouter';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
import Event from './Event';
import EventKnowledge from './EventKnowledge';
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
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import EventEdition from './EventEdition';
import CreateRelationshipButtonComponent from '../../common/menus/RelateComponent';
import RelateComponentContextProvider from '../../common/menus/RelateComponentProvider';

const subscription = graphql`
  subscription RootEventsSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Event {
        ...Event_event
        ...EventEditionContainer_event
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const eventQuery = graphql`
  query RootEventQuery($id: String!) {
    event(id: $id) {
      id
      entity_type
      name
      aliases
      created_at
      updated_at
      ...Event_event
      ...EventKnowledge_event
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

class RootEvent extends Component {
  constructor(props) {
    super(props);
    const {
      params: { eventId },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: eventId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      t,
      location,
      params: { eventId },
    } = this.props;
    const link = `/dashboard/entities/events/${eventId}/knowledge`;
    return (
      <RelateComponentContextProvider>
        <Routes>
          <Route path="/knowledge/*" element={<StixCoreObjectKnowledgeBar
            stixCoreObjectLink={link}
            availableSections={[
              'locations',
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
                                              />}
          >

          </Route>
        </Routes>
        <QueryRenderer
          query={eventQuery}
          variables={{ id: eventId }}
          render={({ props }) => {
            if (props) {
              if (props.event) {
                const { event } = props;
                return (
                  <div
                    style={{
                      paddingRight: location.pathname.includes(
                        `/dashboard/entities/events/${event.id}/knowledge`,
                      )
                        ? 200
                        : 0,
                    }}
                  >
                    <Breadcrumbs variant="object" elements={[
                      { label: t('Entities') },
                      { label: t('Events'), link: '/dashboard/entities/events' },
                      { label: event.name, current: true },
                    ]}
                    />
                    <StixDomainObjectHeader
                      entityType="Event"
                      stixDomainObject={event}
                      enableQuickSubscription={true}
                      EditComponent={<Security needs={[KNOWLEDGE_KNUPDATE]}>
                        <EventEdition eventId={event.id} />
                      </Security>}
                      RelateComponent={<CreateRelationshipButtonComponent
                        id={event.id}
                        defaultStartTime={event.created_at}
                        defaultStopTime={event.updated_at}
                                       />}
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
                            `/dashboard/entities/events/${event.id}/knowledge`,
                          )
                            ? `/dashboard/entities/events/${event.id}/knowledge`
                            : location.pathname
                        }
                      >
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/events/${event.id}`}
                          value={`/dashboard/entities/events/${event.id}`}
                          label={t('Overview')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/events/${event.id}/knowledge/overview`}
                          value={`/dashboard/entities/events/${event.id}/knowledge`}
                          label={t('Knowledge')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/events/${event.id}/analyses`}
                          value={`/dashboard/entities/events/${event.id}/analyses`}
                          label={t('Analyses')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/events/${event.id}/sightings`}
                          value={`/dashboard/entities/events/${event.id}/sightings`}
                          label={t('Sightings')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/events/${event.id}/files`}
                          value={`/dashboard/entities/events/${event.id}/files`}
                          label={t('Data')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/events/${event.id}/history`}
                          value={`/dashboard/entities/events/${event.id}/history`}
                          label={t('History')}
                        />
                      </Tabs>
                    </Box>
                    <Routes>
                      <Route
                        path="/"
                        element={
                          <Event event={props.event} />
                        }
                      />
                      <Route
                        path="/knowledge"
                        element={
                          <Navigate
                            to={`/dashboard/entities/events/${eventId}/knowledge/overview`}
                          />
                        }
                      />
                      <Route
                        path="/knowledge/*"
                        element={
                          <EventKnowledge event={event} />
                        }
                      />
                      <Route
                        path="/analyses"
                        element={
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            stixDomainObjectOrStixCoreRelationship={event}
                          />
                        }
                      />
                      <Route
                        path="/sightings"
                        element={(
                          <EntityStixSightingRelationships
                            entityId={event.id}
                            entityLink={link}
                            noPadding={true}
                            isTo={true}
                          />
                        )}
                      />
                      <Route
                        path="/files"
                        element={ (
                          <FileManager
                            id={eventId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={event}
                          />
                        )}
                      />
                      <Route
                        path="/history"
                        element={ (
                          <StixCoreObjectHistory
                            stixCoreObjectId={eventId}
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
      </RelateComponentContextProvider>
    );
  }
}

RootEvent.propTypes = {
  children: PropTypes.node,
  params: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootEvent);
