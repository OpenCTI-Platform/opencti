import { useMemo, Suspense } from 'react';
import { Route, Routes, Navigate, useLocation, useParams } from 'react-router-dom';
import { graphql, useSubscription, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import { RootEventQuery } from '@components/entities/events/__generated__/RootEventQuery.graphql';
import { RootEventsSubscription } from '@components/entities/events/__generated__/RootEventsSubscription.graphql';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import StixDomainObjectTabsBox from '@components/common/stix_domain_objects/StixDomainObjectTabsBox';
import CreateRelationshipContextProvider from '@components/common/stix_core_relationships/CreateRelationshipContextProvider';
import StixCoreRelationshipCreationFromEntityHeader from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntityHeader';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import Event from './Event';
import EventKnowledge from './EventKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getPaddingRight } from '../../../../utils/utils';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import EventEdition from './EventEdition';
import EventDeletion from './EventDeletion';
import { useEntityLabelResolver } from '../../../../utils/hooks/useEntityLabel';

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
      draftVersion {
        draft_id
        draft_operation
      }
      entity_type
      name
      aliases
      currentUserAccessRight
      ...StixCoreRelationshipCreationFromEntityHeader_stixCoreObject
      ...StixCoreObjectKnowledgeBar_stixCoreObject
      ...Event_event
      ...EventKnowledge_event
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...StixCoreObjectContent_stixCoreObject
      ...StixCoreObjectSharingListFragment
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
  const { t_i18n } = useFormatter();
  const entityLabel = useEntityLabelResolver();
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
              element={(
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
                  data={event}
                />
              )}
            />
          </Routes>
          <div style={{ paddingRight }}>
            <Breadcrumbs elements={[
              { label: t_i18n('Entities') },
              { label: entityLabel('Event', t_i18n('Events')), link: '/dashboard/entities/events' },
              { label: event.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="Event"
              stixDomainObject={event}
              enableQuickSubscription={true}
              EditComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <EventEdition eventId={event.id} />
                </Security>
              )}
              RelateComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <StixCoreRelationshipCreationFromEntityHeader
                    data={event}
                  />
                </Security>
              )}
              DeleteComponent={({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => (
                <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                  <EventDeletion id={event.id} isOpen={isOpen} handleClose={onClose} />
                </Security>
              )}
              redirectToContent={true}
              enableEnrollPlaybook={true}
            />
            <StixDomainObjectTabsBox
              basePath="/dashboard/entities/events"
              entity={event}
              tabs={[
                'overview',
                'knowledge-overview',
                'content',
                'analyses',
                'sightings',
                'files',
                'history',
              ]}
            />
            <Routes>
              <Route
                path="/"
                element={
                  <Event eventData={event} />
                }
              />
              <Route
                path="/knowledge"
                element={(
                  <Navigate
                    replace={true}
                    to={`/dashboard/entities/events/${eventId}/knowledge/overview`}
                  />
                )}
              />
              <Route
                path="/knowledge/*"
                element={(
                  <div key={forceUpdate}>
                    <EventKnowledge eventData={event} />
                  </div>
                )}
              />
              <Route
                path="/content/*"
                element={(
                  <StixCoreObjectContentRoot
                    stixCoreObject={event}
                  />
                )}
              />
              <Route
                path="/analyses"
                element={(
                  <StixCoreObjectOrStixCoreRelationshipContainers
                    stixDomainObjectOrStixCoreRelationship={event}
                  />
                )}
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
                element={(
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
                element={(
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
  const { eventId } = useParams() as { eventId: string };
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
