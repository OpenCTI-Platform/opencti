import React, { useMemo, Suspense } from 'react';
import { Route, Routes, Link, Navigate, useLocation, useParams } from 'react-router-dom';
import { graphql, useSubscription, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { RootEventQuery } from '@components/entities/events/__generated__/RootEventQuery.graphql';
import { RootEventsSubscription } from '@components/entities/events/__generated__/RootEventsSubscription.graphql';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import Event from './Event';
import EventKnowledge from './EventKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import EventPopover from './EventPopover';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import EventEdition from './EventEdition';
import useHelper from '../../../../utils/hooks/useHelper';
import CreateRelationshipContextProvider from '../../common/menus/CreateRelationshipContextProvider';
import CreateRelationshipButtonComponent from '../../common/menus/CreateRelationshipButtonComponent';

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

type RootEventProps = {
  eventId: string;
  queryRef: PreloadedQuery<RootEventQuery>;
};

const RootEvent = ({ eventId, queryRef }: RootEventProps) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootEventsSubscription>>(() => ({
    subscription,
    variables: { id: eventId },
  }), [eventId]);

  const location = useLocation();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const { t_i18n } = useFormatter();
  useSubscription<RootEventsSubscription>(subConfig);

  const {
    event,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootEventQuery>(eventQuery, queryRef);

  const { forceUpdate } = useForceUpdate();

  const link = `/dashboard/entities/events/${eventId}/knowledge`;
  const paddingRight = getPaddingRight(location.pathname, eventId, '/dashboard/entities/events');
  return (
    <CreateRelationshipContextProvider>
      {event ? (
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
            <Breadcrumbs elements={[
              { label: t_i18n('Entities') },
              { label: t_i18n('Events'), link: '/dashboard/entities/events' },
              { label: event.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="Event"
              stixDomainObject={event}
              enableQuickSubscription={true}
              PopoverComponent={<EventPopover id={event.id}/>}
              EditComponent={isFABReplaced && (
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <EventEdition eventId={event.id} />
                </Security>
              )}
              RelateComponent={CreateRelationshipButtonComponent}
            />
            <Box
              sx={{
                borderBottom: 1,
                borderColor: 'divider',
                marginBottom: 3,
              }}
            >
              <Tabs
                value={getCurrentTab(location.pathname, event.id, '/dashboard/entities/events')}
              >
                <Tab
                  component={Link}
                  to={`/dashboard/entities/events/${event.id}`}
                  value={`/dashboard/entities/events/${event.id}`}
                  label={t_i18n('Overview')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/events/${event.id}/knowledge/overview`}
                  value={`/dashboard/entities/events/${event.id}/knowledge`}
                  label={t_i18n('Knowledge')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/events/${event.id}/content`}
                  value={`/dashboard/entities/events/${event.id}/content`}
                  label={t_i18n('Content')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/events/${event.id}/analyses`}
                  value={`/dashboard/entities/events/${event.id}/analyses`}
                  label={t_i18n('Analyses')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/events/${event.id}/sightings`}
                  value={`/dashboard/entities/events/${event.id}/sightings`}
                  label={t_i18n('Sightings')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/events/${event.id}/files`}
                  value={`/dashboard/entities/events/${event.id}/files`}
                  label={t_i18n('Data')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/events/${event.id}/history`}
                  value={`/dashboard/entities/events/${event.id}/history`}
                  label={t_i18n('History')}
                />
              </Tabs>
            </Box>
            <Routes>
              <Route
                path="/"
                element={
                  <Event eventData={event} />
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
                  <div key={forceUpdate}>
                    <EventKnowledge event={event} />
                  </div>
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
                element={ (
                  <FileManager
                    id={eventId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
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
      ) : (
        <ErrorNotFound />
      )}
    </CreateRelationshipContextProvider>
  );
};
const Root = () => {
  const { eventId } = useParams() as { eventId: string; };
  const queryRef = useQueryLoading<RootEventQuery>(eventQuery, {
    id: eventId,
  });

  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootEvent eventId={eventId} queryRef={queryRef} />
        </Suspense>
      )}
    </>
  );
};

export default Root;
