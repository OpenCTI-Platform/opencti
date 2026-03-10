import { Suspense, useMemo } from 'react';
import { Navigate, Route, Routes, useLocation, useParams } from 'react-router-dom';
import { graphql, useSubscription, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import StixDomainObjectTabsBox from '@components/common/stix_domain_objects/StixDomainObjectTabsBox';
import CreateRelationshipContextProvider from '@components/common/stix_core_relationships/CreateRelationshipContextProvider';
import StixCoreRelationshipCreationFromEntityHeader from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntityHeader';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import Channel from './Channel';
import ChannelKnowledge from './ChannelKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getPaddingRight } from '../../../../utils/utils';
import { RootChannelSubscription } from './__generated__/RootChannelSubscription.graphql';
import { RootChannelQuery } from './__generated__/RootChannelQuery.graphql';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import ChannelEdition from './ChannelEdition';
import ChannelDeletion from './ChannelDeletion';
import { useEntityLabelResolver } from '../../../../utils/hooks/useEntityLabel';

const subscription = graphql`
  subscription RootChannelSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Channel {
        ...Channel_channel
        ...ChannelEditionContainer_channel
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const channelQuery = graphql`
  query RootChannelQuery($id: String!) {
    channel(id: $id) {
      id
      draftVersion {
        draft_id
        draft_operation
      }
      standard_id
      entity_type
      name
      aliases
      x_opencti_graph_data
      currentUserAccessRight
      ...StixCoreRelationshipCreationFromEntityHeader_stixCoreObject
      ...StixCoreObjectKnowledgeBar_stixCoreObject
      ...Channel_channel
      ...ChannelKnowledge_channel
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

type RootChannelProps = {
  channelId: string;
  queryRef: PreloadedQuery<RootChannelQuery>;
};

const RootChannel = ({ queryRef, channelId }: RootChannelProps) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootChannelSubscription>>(() => ({
    subscription,
    variables: { id: channelId },
  }), [channelId]);

  const location = useLocation();
  const { t_i18n } = useFormatter();
  const entityLabel = useEntityLabelResolver();
  useSubscription<RootChannelSubscription>(subConfig);

  const {
    channel,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootChannelQuery>(channelQuery, queryRef);

  const { forceUpdate } = useForceUpdate();

  const paddingRight = getPaddingRight(location.pathname, channelId, '/dashboard/arsenal/channels');
  const link = `/dashboard/arsenal/channels/${channelId}/knowledge`;
  return (
    <CreateRelationshipContextProvider>
      {channel ? (
        <>
          <Routes>
            <Route
              path="/knowledge/*"
              element={(
                <StixCoreObjectKnowledgeBar
                  stixCoreObjectLink={link}
                  availableSections={[
                    'victimology',
                    'threats',
                    'threat_actors',
                    'intrusion_sets',
                    'campaigns',
                    'incidents',
                    'malwares',
                    'attack_patterns',
                    'vulnerabilities',
                    'observables',
                    'sightings',
                    'channels',
                  ]}
                  data={channel}
                />
              )}
            />
          </Routes>
          <div style={{ paddingRight }}>
            <Breadcrumbs elements={[
              { label: t_i18n('Arsenal') },
              { label: entityLabel('Channel', t_i18n('Channels')), link: '/dashboard/arsenal/channels' },
              { label: channel.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="Channel"
              stixDomainObject={channel}
              EditComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <ChannelEdition channelId={channel.id} />
                </Security>
              )}
              RelateComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <StixCoreRelationshipCreationFromEntityHeader
                    data={channel}
                  />
                </Security>
              )}
              DeleteComponent={({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => (
                <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                  <ChannelDeletion id={channel.id} isOpen={isOpen} handleClose={onClose} />
                </Security>
              )}
              enableEnricher={true}
              enableQuickSubscription={true}
              redirectToContent={true}
              enableEnrollPlaybook={true}
            />
            <StixDomainObjectTabsBox
              basePath="/dashboard/arsenal/channels"
              entity={channel}
              tabs={[
                'overview',
                'knowledge-overview',
                'content',
                'analyses',
                'files',
                'history',
              ]}
            />
            <Routes>
              <Route
                path="/"
                element={(
                  <Channel channelData={channel} />
                )}
              />
              <Route
                path="/knowledge"
                element={(
                  <Navigate
                    replace={true}
                    to={`/dashboard/arsenal/channels/${channelId}/knowledge/overview`}
                  />
                )}
              />
              <Route
                path="/knowledge/*"
                element={(
                  <div key={forceUpdate}>
                    <ChannelKnowledge channelData={channel} />
                  </div>
                )}
              />
              <Route
                path="/content/*"
                element={(
                  <StixCoreObjectContentRoot
                    stixCoreObject={channel}
                  />
                )}
              />
              <Route
                path="/analyses/*"
                element={(
                  <StixCoreObjectOrStixCoreRelationshipContainers
                    stixDomainObjectOrStixCoreRelationship={channel}
                  />
                )}
              />
              <Route
                path="/files"
                element={(
                  <FileManager
                    id={channelId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={channel}
                  />
                )}
              />
              <Route
                path="/history"
                element={(
                  <StixCoreObjectHistory
                    stixCoreObjectId={channelId}
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
  const { channelId } = useParams() as { channelId: string };
  const queryRef = useQueryLoading<RootChannelQuery>(channelQuery, {
    id: channelId,
  });

  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootChannel queryRef={queryRef} channelId={channelId} />
        </Suspense>
      )}
    </>
  );
};

export default Root;
