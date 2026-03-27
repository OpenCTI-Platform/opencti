import { useMemo, Suspense } from 'react';
import { Route, Routes, useLocation, useParams } from 'react-router-dom';
import { graphql, useSubscription, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import { RootEventQuery } from '@components/entities/events/__generated__/RootEventQuery.graphql';
import { RootEventsSubscription } from '@components/entities/events/__generated__/RootEventsSubscription.graphql';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import CreateRelationshipContextProvider from '@components/common/stix_core_relationships/CreateRelationshipContextProvider';
import StixCoreRelationshipCreationFromEntityHeader from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntityHeader';
import StixDomainObjectMain from '@components/common/stix_domain_objects/StixDomainObjectMain';
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
import { PATH_EVENT, PATH_EVENTS } from '@components/common/routes/paths';

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
  useSubscription<RootEventsSubscription>(subConfig);

  const {
    event,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootEventQuery>(eventQuery, queryRef);

  const { forceUpdate } = useForceUpdate();

  const basePath = PATH_EVENT(eventId);
  const link = `${basePath}/knowledge`;
  const paddingRight = getPaddingRight(location.pathname, basePath);
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
              { label: t_i18n('Events'), link: PATH_EVENTS },
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
            <StixDomainObjectMain
              basePath={basePath}
              pages={{
                overview:
                  <Event eventData={event} />,
                knowledge: (
                  <div key={forceUpdate}>
                    <EventKnowledge eventData={event} />
                  </div>
                ),
                content: (
                  <StixCoreObjectContentRoot
                    stixCoreObject={event}
                  />
                ),
                analyses: (
                  <StixCoreObjectOrStixCoreRelationshipContainers
                    stixDomainObjectOrStixCoreRelationship={event}
                  />
                ),
                sightings: (
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
                ),
                files: (
                  <FileManager
                    id={eventId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={event}
                  />
                ),
                history: (
                  <StixCoreObjectHistory
                    stixCoreObjectId={eventId}
                  />
                ),
              }}
            />
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
