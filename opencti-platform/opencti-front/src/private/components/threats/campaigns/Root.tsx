import { Suspense, useMemo } from 'react';
import { Route, Routes, Navigate, useParams, useLocation } from 'react-router-dom';
import { graphql, PreloadedQuery, useSubscription, usePreloadedQuery } from 'react-relay';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import { RootCampaignSubscription } from '@components/threats/campaigns/__generated__/RootCampaignSubscription.graphql';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import AIInsights from '@components/common/ai/AIInsights';
import StixCoreObjectSecurityCoverage from '@components/common/stix_core_objects/StixCoreObjectSecurityCoverage';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import Campaign from './Campaign';
import CampaignKnowledge from './CampaignKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixDomainObjectTabsBox from '@components/common/stix_domain_objects/StixDomainObjectTabsBox';
import FileManager from '../../common/files/FileManager';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getPaddingRight } from '../../../../utils/utils';
import { RootCampaignQuery } from './__generated__/RootCampaignQuery.graphql';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import CampaignEdition from './CampaignEdition';
import CampaignDeletion from './CampaignDeletion';
import StixCoreRelationshipCreationFromEntityHeader from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntityHeader';
import CreateRelationshipContextProvider from '../../common/stix_core_relationships/CreateRelationshipContextProvider';
import { useEntityTypeDisplayName } from '../../../../utils/hooks/useEntityTypeDisplayName';

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
      securityCoverage {
        id
        coverage_information {
          coverage_name
          coverage_score
        }
      }
      ...StixCoreRelationshipCreationFromEntityHeader_stixCoreObject
      ...StixCoreObjectKnowledgeBar_stixCoreObject
      ...Campaign_campaign
      ...CampaignKnowledge_campaign
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

type RootCampaignProps = {
  campaignId: string;
  queryRef: PreloadedQuery<RootCampaignQuery>;
};

const RootCampaign = ({ campaignId, queryRef }: RootCampaignProps) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootCampaignSubscription>>(() => ({
    subscription,
    variables: { id: campaignId },
  }), [campaignId]);
  const location = useLocation();
  const { t_i18n } = useFormatter();
  const entityTypeDisplayName = useEntityTypeDisplayName();
  useSubscription<RootCampaignSubscription>(subConfig);
  const {
    campaign,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootCampaignQuery>(campaignQuery, queryRef);
  const { forceUpdate } = useForceUpdate();
  const link = `/dashboard/threats/campaigns/${campaignId}/knowledge`;
  const isOverview = location.pathname === `/dashboard/threats/campaigns/${campaignId}`;
  const paddingRight = getPaddingRight(location.pathname, campaignId, '/dashboard/threats/campaigns');
  return (
    <CreateRelationshipContextProvider>
      {campaign ? (
        <>
          <Routes>
            <Route
              path="/knowledge/*"
              element={(
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
                  data={campaign}
                  attribution={['Intrusion-Set', 'Threat-Actor-Individual', 'Threat-Actor-Group']}
                />
              )}
            />
          </Routes>
          <div style={{ paddingRight }}>
            <Breadcrumbs elements={[
              { label: t_i18n('Threats') },
              { label: entityTypeDisplayName('Campaign', t_i18n('Campaigns')), link: '/dashboard/threats/campaigns' },
              { label: campaign.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="Campaign"
              stixDomainObject={campaign}
              EditComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <CampaignEdition campaignId={campaign.id} />
                </Security>
              )}
              RelateComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <StixCoreRelationshipCreationFromEntityHeader
                    data={campaign}
                  />
                </Security>
              )}
              DeleteComponent={({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => (
                <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                  <CampaignDeletion id={campaign.id} isOpen={isOpen} handleClose={onClose} />
                </Security>
              )}
              enableEnricher={true}
              enableQuickSubscription={true}
              redirectToContent={true}
              enableEnrollPlaybook={true}
            />
            <StixDomainObjectTabsBox
              basePath="/dashboard/threats/campaigns"
              entity={campaign}
              tabs={[
                'overview',
                'knowledge-overview',
                'content',
                'analyses',
                'files',
                'history',
              ]}
              extraActions={isOverview && (
                <>
                  <AIInsights id={campaign.id} />
                  <StixCoreObjectSecurityCoverage id={campaign.id} coverage={campaign.securityCoverage} />
                </>
              )}
            />
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
                element={(
                  <div key={forceUpdate}>
                    <CampaignKnowledge campaignData={campaign} />
                  </div>
                )}
              />
              <Route
                path="/content/*"
                element={(
                  <StixCoreObjectContentRoot
                    stixCoreObject={campaign}
                  />
                )}
              />
              <Route
                path="/analyses"
                element={
                  <StixCoreObjectOrStixCoreRelationshipContainers stixDomainObjectOrStixCoreRelationship={campaign} />
                }
              />
              <Route
                path="/files"
                element={(
                  <FileManager
                    id={campaignId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={campaign}
                  />
                )}
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
    </CreateRelationshipContextProvider>
  );
};

const Root = () => {
  const { campaignId } = useParams() as { campaignId: string };
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
