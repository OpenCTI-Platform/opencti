import React, { useMemo } from 'react';
import { Link, Navigate, Route, Routes, useLocation, useParams } from 'react-router-dom';
import { graphql, PreloadedQuery, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import StixCoreObjectContentRoot from '@components/common/stix_core_objects/StixCoreObjectContentRoot';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import AIInsights from '@components/common/ai/AIInsights';
import StixCoreObjectSimulationResultContainer from '../../common/stix_core_objects/StixCoreObjectSimulationResultContainer';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import { RootThreatActorIndividualQuery } from './__generated__/RootThreatActorIndividualQuery.graphql';
import { RootThreatActorIndividualSubscription } from './__generated__/RootThreatActorIndividualSubscription.graphql';
import ThreatActorIndividualPopover from './ThreatActorIndividualPopover';
import ThreatActorIndividual from './ThreatActorIndividual';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import ThreatActorIndividualKnowledge from './ThreatActorIndividualKnowledge';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import ThreatActorIndividualEdition from './ThreatActorIndividualEdition';
import useHelper from '../../../../utils/hooks/useHelper';

const subscription = graphql`
  subscription RootThreatActorIndividualSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on ThreatActorIndividual {
        ...ThreatActorIndividual_ThreatActorIndividual
        ...ThreatActorIndividualEditionOverview_ThreatActorIndividual
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...PictureManagementViewer_entity
    }
  }
`;

const ThreatActorIndividualQuery = graphql`
  query RootThreatActorIndividualQuery($id: String!, $relatedRelationshipTypes: [String!]) {
    threatActorIndividual(id: $id) {
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
      ...StixCoreObjectKnowledgeBar_stixCoreObject @arguments(relatedRelationshipTypes: $relatedRelationshipTypes)
      ...ThreatActorIndividual_ThreatActorIndividual
      ...ThreatActorIndividualKnowledge_ThreatActorIndividual
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...PictureManagementViewer_entity
      ...StixCoreObjectContent_stixCoreObject
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
    connectorsForImport {
      ...FileManager_connectorsImport
    }
  }
`;

const THREAT_ACTOR_INDIVIDUAL_RELATED_RELATIONSHIP_TYPES = ['related-to', 'part-of', 'impersonates', 'known-as'];

type RootThreatActorIndividualProps = {
  threatActorIndividualId: string;
  queryRef: PreloadedQuery<RootThreatActorIndividualQuery>
};

const RootThreatActorIndividualComponent = ({
  queryRef,
  threatActorIndividualId,
}: RootThreatActorIndividualProps) => {
  const subConfig = useMemo<
  GraphQLSubscriptionConfig<RootThreatActorIndividualSubscription>
  >(
    () => ({
      subscription,
      variables: { id: threatActorIndividualId },
    }),
    [threatActorIndividualId],
  );
  const location = useLocation();
  const { t_i18n } = useFormatter();
  useSubscription<RootThreatActorIndividualSubscription>(subConfig);
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const {
    threatActorIndividual,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootThreatActorIndividualQuery>(
    ThreatActorIndividualQuery,
    queryRef,
  );
  const { forceUpdate } = useForceUpdate();
  const paddingRight = getPaddingRight(location.pathname, threatActorIndividualId, '/dashboard/threats/threat_actors_individual');
  const link = `/dashboard/threats/threat_actors_individual/${threatActorIndividualId}/knowledge`;
  return (
    <>
      {threatActorIndividual ? (
        <>
          <Routes>
            <Route
              path="/knowledge/*"
              element={
                <StixCoreObjectKnowledgeBar
                  stixCoreObjectLink={link}
                  availableSections={[
                    'victimology',
                    'threat_actors',
                    'intrusion_sets',
                    'campaigns',
                    'incidents',
                    'organizations',
                    'malwares',
                    'attack_patterns',
                    'channels',
                    'narratives',
                    'tools',
                    'vulnerabilities',
                    'indicators',
                    'observables',
                    'infrastructures',
                    'sightings',
                    'countries',
                  ]}
                  data={threatActorIndividual}
                />
             }
            />
          </Routes>
          <div style={{ paddingRight }}>
            <Breadcrumbs elements={[
              { label: t_i18n('Threats') },
              { label: t_i18n('Threat actors (individual)'), link: '/dashboard/threats/threat_actors_individual' },
              { label: threatActorIndividual.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="Threat-Actor-Individual"
              stixDomainObject={threatActorIndividual}
              PopoverComponent={ThreatActorIndividualPopover}
              EditComponent={isFABReplaced && (
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <ThreatActorIndividualEdition
                    threatActorIndividualId={threatActorIndividual.id}
                  />
                </Security>
              )}
              enableEnricher={isFABReplaced}
              enableQuickSubscription={true}
            />
            <Box
              sx={{
                borderBottom: 1,
                borderColor: 'divider',
                marginBottom: 3,
                display: 'flex',
                justifyContent: 'space-between',
                alignItem: 'center',
              }}
            >
              <Tabs
                value={getCurrentTab(location.pathname, threatActorIndividual.id, '/dashboard/threats/threat_actors_individual')}
              >
                <Tab
                  component={Link}
                  to={`/dashboard/threats/threat_actors_individual/${threatActorIndividual.id}`}
                  value={`/dashboard/threats/threat_actors_individual/${threatActorIndividual.id}`}
                  label={t_i18n('Overview')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/threats/threat_actors_individual/${threatActorIndividual.id}/knowledge/overview`}
                  value={`/dashboard/threats/threat_actors_individual/${threatActorIndividual.id}/knowledge`}
                  label={t_i18n('Knowledge')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/threats/threat_actors_individual/${threatActorIndividual.id}/content`}
                  value={`/dashboard/threats/threat_actors_individual/${threatActorIndividual.id}/content`}
                  label={t_i18n('Content')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/threats/threat_actors_individual/${threatActorIndividual.id}/analyses`}
                  value={`/dashboard/threats/threat_actors_individual/${threatActorIndividual.id}/analyses`}
                  label={t_i18n('Analyses')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/threats/threat_actors_individual/${threatActorIndividual.id}/files`}
                  value={`/dashboard/threats/threat_actors_individual/${threatActorIndividual.id}/files`}
                  label={t_i18n('Data')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/threats/threat_actors_individual/${threatActorIndividual.id}/history`}
                  value={`/dashboard/threats/threat_actors_individual/${threatActorIndividual.id}/history`}
                  label={t_i18n('History')}
                />
              </Tabs>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px' }}>
                <AIInsights id={threatActorIndividual.id}/>
                <StixCoreObjectSimulationResultContainer id={threatActorIndividual.id} type="threat"/>
              </div>
            </Box>
            <Routes>
              <Route
                path="/"
                element={
                  <ThreatActorIndividual threatActorIndividualData={threatActorIndividual}/>
                  }
              />
              <Route
                path="/knowledge"
                element={
                  <Navigate to={`/dashboard/threats/threat_actors_individual/${threatActorIndividual.id}/knowledge/overview`} replace={true} />
                }
              />
              <Route
                path="/knowledge/*"
                element={
                  <div key={forceUpdate}>
                    <ThreatActorIndividualKnowledge
                      threatActorIndividualData={threatActorIndividual}
                      relatedRelationshipTypes={THREAT_ACTOR_INDIVIDUAL_RELATED_RELATIONSHIP_TYPES}
                    />
                  </div>
                }
              />
              <Route
                path="/content/*"
                element={
                  <StixCoreObjectContentRoot
                    stixCoreObject={threatActorIndividual}
                  />
                }
              />
              <Route
                path="/analyses"
                element={
                  <StixCoreObjectOrStixCoreRelationshipContainers stixDomainObjectOrStixCoreRelationship={threatActorIndividual} />
                }
              />
              <Route
                path="/files"
                element={
                  <FileManager
                    id={threatActorIndividualId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={threatActorIndividual}
                  />
                }
              />
              <Route
                path="/history"
                element={
                  <StixCoreObjectHistory stixCoreObjectId={threatActorIndividualId} />
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
  const { threatActorIndividualId } = useParams() as {
    threatActorIndividualId: string;
  };
  const queryRef = useQueryLoading<RootThreatActorIndividualQuery>(
    ThreatActorIndividualQuery,
    {
      id: threatActorIndividualId,
      relatedRelationshipTypes: THREAT_ACTOR_INDIVIDUAL_RELATED_RELATIONSHIP_TYPES,
    },
  );
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootThreatActorIndividualComponent
            queryRef={queryRef}
            threatActorIndividualId={threatActorIndividualId}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default Root;
