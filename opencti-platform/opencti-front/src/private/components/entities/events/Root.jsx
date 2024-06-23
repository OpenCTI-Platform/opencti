import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Routes, Link, Navigate } from 'react-router-dom';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import withRouter from '../../../../utils/compat-router/withRouter';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
import Event from './Event';
import EventKnowledge from './EventKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import EventPopover from './EventPopover';
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
      stixCoreObjectsDistribution(field: "entity_type", operation: count) {
        label
        value
      }
      ...Event_event
      ...EventKnowledge_event
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
      <>
        <QueryRenderer
          query={eventQuery}
          variables={{ id: eventId }}
          render={({ props }) => {
            if (props) {
              if (props.event) {
                const { event } = props;
                const paddingRight = getPaddingRight(location.pathname, event.id, '/dashboard/entities/events');
                return (
                  <>
                    <Routes>
                      <Route
                        path="/knowledge/*"
                        element={
                          <StixCoreObjectKnowledgeBar
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
                            stixCoreObjectsDistribution={event.stixCoreObjectsDistribution}
                          />
                       }
                      />
                    </Routes>
                    <div style={{ paddingRight }}>
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
                        PopoverComponent={<EventPopover />}
                      />
                      <Box
                        sx={{
                          borderBottom: 1,
                          borderColor: 'divider',
                          marginBottom: 4,
                        }}
                      >
                        <Tabs
                          value={getCurrentTab(location.pathname, event.id, '/dashboard/entities/events')}
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
                            to={`/dashboard/entities/events/${event.id}/content`}
                            value={`/dashboard/entities/events/${event.id}/content`}
                            label={t('Content')}
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
                              replace={true}
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
                          path="/content/*"
                          element={
                            <StixCoreObjectContentRoot
                              stixCoreObject={event}
                            />
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

RootEvent.propTypes = {
  children: PropTypes.node,
  params: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootEvent);
