import React, { Suspense, useMemo } from 'react';
import { Link, Navigate, Route, Routes, useLocation, useParams } from 'react-router-dom';
import { graphql, useSubscription, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import Channel from './Channel';
import ChannelKnowledge from './ChannelKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import ChannelPopover from './ChannelPopover';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';
import { RootChannelSubscription } from './__generated__/RootChannelSubscription.graphql';
import { RootChannelQuery } from './__generated__/RootChannelQuery.graphql';

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
      standard_id
      entity_type
      name
      aliases
      x_opencti_graph_data
      stixCoreObjectsDistribution(field: "entity_type", operation: count) {
        label
        value
      }   
      ...Channel_channel
      ...ChannelKnowledge_channel
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
  useSubscription<RootChannelSubscription>(subConfig);

  const {
    channel,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootChannelQuery>(channelQuery, queryRef);

  const paddingRight = getPaddingRight(location.pathname, channelId, '/dashboard/arsenal/channels');
  const link = `/dashboard/arsenal/channels/${channelId}/knowledge`;
  return (
    <>
      {channel ? (
        <>
          <Routes>
            <Route
              path="/knowledge/*"
              element= {
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
                  stixCoreObjectsDistribution={channel.stixCoreObjectsDistribution}
                />
              }
            />
          </Routes>
          <div style={{ paddingRight }}>
            <Breadcrumbs variant="object" elements={[
              { label: t_i18n('Arsenal') },
              { label: t_i18n('Channels'), link: '/dashboard/arsenal/channels' },
              { label: channel.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="Channel"
              stixDomainObject={channel}
              PopoverComponent={<ChannelPopover />}
              enableQuickSubscription={true}
            />
            <Box
              sx={{
                borderBottom: 1,
                borderColor: 'divider',
                marginBottom: 4,
              }}
            >
              <Tabs
                value={getCurrentTab(location.pathname, channel.id, '/dashboard/arsenal/channels')}
              >
                <Tab
                  component={Link}
                  to={`/dashboard/arsenal/channels/${channel.id}`}
                  value={`/dashboard/arsenal/channels/${channel.id}`}
                  label={t_i18n('Overview')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/arsenal/channels/${channel.id}/knowledge/overview`}
                  value={`/dashboard/arsenal/channels/${channel.id}/knowledge`}
                  label={t_i18n('Knowledge')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/arsenal/channels/${channel.id}/content`}
                  value={`/dashboard/arsenal/channels/${channel.id}/content`}
                  label={t_i18n('Content')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/arsenal/channels/${channel.id}/analyses`}
                  value={`/dashboard/arsenal/channels/${channel.id}/analyses`}
                  label={t_i18n('Analyses')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/arsenal/channels/${channel.id}/files`}
                  value={`/dashboard/arsenal/channels/${channel.id}/files`}
                  label={t_i18n('Data')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/arsenal/channels/${channel.id}/history`}
                  value={`/dashboard/arsenal/channels/${channel.id}/history`}
                  label={t_i18n('History')}
                />
              </Tabs>
            </Box>
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
                element={<ChannelKnowledge channel={channel} />}
              />
              <Route
                path="/content/*"
                element={
                  <StixCoreObjectContentRoot
                    stixCoreObject={channel}
                  />
                }
              />
              <Route
                path="/analyses/*"
                element={
                  <StixCoreObjectOrStixCoreRelationshipContainers
                    stixDomainObjectOrStixCoreRelationship={channel}
                  />
                }
              />
              <Route
                path="/files"
                element={ (
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
                element={ (
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
    </>
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
