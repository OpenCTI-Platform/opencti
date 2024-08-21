import React, { Suspense, useMemo } from 'react';
import { Route, Routes, Link, Navigate, useParams, useLocation } from 'react-router-dom';
import { graphql, PreloadedQuery, useSubscription, usePreloadedQuery } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import { RootCampaignSubscription } from '@components/threats/campaigns/__generated__/RootCampaignSubscription.graphql';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import StixCoreObjectSimulationResult from '../../common/stix_core_objects/StixCoreObjectSimulationResult';
import Campaign from './Campaign';
import CampaignKnowledge from './CampaignKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import CampaignPopover from './CampaignPopover';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';
import { RootCampaignQuery } from './__generated__/RootCampaignQuery.graphql';

const subscription = graphql`
  subscription RootCampaignSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Campaign {
        ...Campaign_campaign
        ...CampaignEditionContainer_campaign
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const campaignQuery = graphql`
  query RootCampaignQuery($id: String!) {
    campaign(id: $id) {
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
      ...Campaign_campaign
      ...CampaignKnowledge_campaign
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

type RootCampaignProps = {
  campaignId: string;
  queryRef: PreloadedQuery<RootCampaignQuery>
};

const RootCampaign = ({ campaignId, queryRef }: RootCampaignProps) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootCampaignSubscription>>(() => ({
    subscription,
    variables: { id: campaignId },
  }), [campaignId]);

  const location = useLocation();
  const { t_i18n } = useFormatter();

  useSubscription<RootCampaignSubscription>(subConfig);

  const {
    campaign,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootCampaignQuery>(campaignQuery, queryRef);

  const link = `/dashboard/threats/campaigns/${campaignId}/knowledge`;
  const isOverview = location.pathname === `/dashboard/threats/campaigns/${campaignId}`;
  const paddingRight = getPaddingRight(location.pathname, campaignId, '/dashboard/threats/campaigns');
  return (
    <>
      {campaign ? (
        <>
          <Routes>
            <Route
              path="/knowledge/*"
              element={
                <StixCoreObjectKnowledgeBar
                  stixCoreObjectLink={link}
                  availableSections={[
                    'attribution',
                    'victimology',
                    'incidents',
                    'malwares',
                    'tools',
                    'channels',
                    'narratives',
                    'attack_patterns',
                    'vulnerabilities',
                    'indicators',
                    'observables',
                    'infrastructures',
                    'sightings',
                  ]}
                  stixCoreObjectsDistribution={campaign.stixCoreObjectsDistribution}
                  attribution={['Intrusion-Set', 'Threat-Actor-Individual', 'Threat-Actor-Group']}
                />
              }
            />
          </Routes>
          <div style={{ paddingRight }}>
            <Breadcrumbs variant="object" elements={[
              { label: t_i18n('Threats') },
              { label: t_i18n('Campaigns'), link: '/dashboard/threats/campaigns' },
              { label: campaign.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="Campaign"
              stixDomainObject={campaign}
              PopoverComponent={<CampaignPopover />}
              enableQuickSubscription={true}
            />
            <Box
              sx={{
                borderBottom: 1,
                borderColor: 'divider',
                marginBottom: 4,
                display: 'flex',
                justifyContent: 'space-between',
                alignItem: 'center',
              }}
            >
              <Tabs
                value={getCurrentTab(location.pathname, campaign.id, '/dashboard/threats/campaigns')}
              >
                <Tab
                  component={Link}
                  to={`/dashboard/threats/campaigns/${campaign.id}`}
                  value={`/dashboard/threats/campaigns/${campaign.id}`}
                  label={t_i18n('Overview')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/threats/campaigns/${campaign.id}/knowledge/overview`}
                  value={`/dashboard/threats/campaigns/${campaign.id}/knowledge`}
                  label={t_i18n('Knowledge')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/threats/campaigns/${campaign.id}/content`}
                  value={`/dashboard/threats/campaigns/${campaign.id}/content`}
                  label={t_i18n('Content')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/threats/campaigns/${campaign.id}/analyses`}
                  value={`/dashboard/threats/campaigns/${campaign.id}/analyses`}
                  label={t_i18n('Analyses')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/threats/campaigns/${campaign.id}/files`}
                  value={`/dashboard/threats/campaigns/${campaign.id}/files`}
                  label={t_i18n('Data')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/threats/campaigns/${campaign.id}/history`}
                  value={`/dashboard/threats/campaigns/${campaign.id}/history`}
                  label={t_i18n('History')}
                />
              </Tabs>
              {isOverview && (
                <StixCoreObjectSimulationResult id={campaign.id} type="threat" />
              )}
            </Box>
            <Routes>
              <Route
                path="/"
                element={
                  <Campaign campaignData={campaign} />
                }
              />
              <Route
                path="/knowledge"
                element={
                  <Navigate to={`/dashboard/threats/campaigns/${campaignId}/knowledge/overview`} replace={true} />
                }
              />
              <Route
                path="/knowledge/*"
                element={<CampaignKnowledge campaign={campaign} />}
              />
              <Route
                path="/content/*"
                element={
                  <StixCoreObjectContentRoot
                    stixCoreObject={campaign}
                  />
                }
              />
              <Route
                path="/analyses"
                element={
                  <StixCoreObjectOrStixCoreRelationshipContainers stixDomainObjectOrStixCoreRelationship={campaign} />
                }
              />
              <Route
                path="/files"
                element={
                  <FileManager
                    id={campaignId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={campaign}
                  />
                }
              />
              <Route
                path="/history"
                element={
                  <StixCoreObjectHistory stixCoreObjectId={campaignId} />
                }
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
  const { campaignId } = useParams() as { campaignId: string; };
  const queryRef = useQueryLoading<RootCampaignQuery>(campaignQuery, {
    id: campaignId,
  });

  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootCampaign queryRef={queryRef} campaignId={campaignId} />
        </Suspense>
      )}
    </>
  );
};

export default Root;
