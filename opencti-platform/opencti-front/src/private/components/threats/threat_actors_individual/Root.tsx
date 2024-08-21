import React, { useMemo } from 'react';
import { Link, Route, Routes, useParams, useLocation, Navigate } from 'react-router-dom';
import { graphql, PreloadedQuery, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import StixCoreObjectContentRoot from '@components/common/stix_core_objects/StixCoreObjectContentRoot';
import StixCoreObjectSimulationResult from '../../common/stix_core_objects/StixCoreObjectSimulationResult';
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
  query RootThreatActorIndividualQuery($id: String!) {
    threatActorIndividual(id: $id) {
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

  const {
    threatActorIndividual,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootThreatActorIndividualQuery>(
    ThreatActorIndividualQuery,
    queryRef,
  );

  const isOverview = location.pathname === `/dashboard/threats/threat_actors_individual/${threatActorIndividualId}`;
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
                  stixCoreObjectsDistribution={threatActorIndividual.stixCoreObjectsDistribution}
                />
             }
            />
          </Routes>
          <div style={{ paddingRight }}>
            <Breadcrumbs variant="object" elements={[
              { label: t_i18n('Threats') },
              { label: t_i18n('Threat actors (individual)'), link: '/dashboard/threats/threat_actors_individual' },
              { label: threatActorIndividual.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="Threat-Actor-Individual"
              stixDomainObject={threatActorIndividual}
              PopoverComponent={ThreatActorIndividualPopover}
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
              {isOverview && (
                <StixCoreObjectSimulationResult id={threatActorIndividual.id} type="threat" />
              )}
            </Box>
            <Routes>
              <Route
                path="/"
                element={
                  <ThreatActorIndividual threatActorIndividualData={threatActorIndividual} />
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
                element={<ThreatActorIndividualKnowledge threatActorIndividualData={threatActorIndividual} />}
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
