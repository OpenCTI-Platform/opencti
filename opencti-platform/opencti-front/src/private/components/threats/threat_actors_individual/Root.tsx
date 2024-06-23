/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Link, Route, Routes, useParams, useLocation, Navigate } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
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

const RootThreatActorIndividualComponent = ({
  queryRef,
  threatActorIndividualId,
}) => {
  const subConfig = useMemo<
  GraphQLSubscriptionConfig<RootThreatActorIndividualSubscription>
  >(
    () => ({
      subscription,
      variables: { id: threatActorIndividualId },
    }),
    [threatActorIndividualId],
  );
  useSubscription(subConfig);
  const location = useLocation();
  const { t_i18n } = useFormatter();
  const {
    threatActorIndividual: data,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootThreatActorIndividualQuery>(
    ThreatActorIndividualQuery,
    queryRef,
  );
  const isOverview = location.pathname === `/dashboard/threats/threat_actors_individual/${data.id}`;
  const link = `/dashboard/threats/threat_actors_individual/${data.id}/knowledge`;
  const paddingRight = getPaddingRight(location.pathname, data.id, '/dashboard/threats/threat_actors_individual');
  return (
    <>
      {data ? (
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
                  stixCoreObjectsDistribution={data.stixCoreObjectsDistribution}
                />
             }
            />
          </Routes>
          <div style={{ paddingRight }}>
            <Breadcrumbs variant="object" elements={[
              { label: t_i18n('Threats') },
              { label: t_i18n('Threat actors (individual)'), link: '/dashboard/threats/threat_actors_individual' },
              { label: data.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="Threat-Actor-Individual"
              stixDomainObject={data}
              PopoverComponent={ThreatActorIndividualPopover}
              enableQuickSubscription={true}
            />
            <Box
              sx={{ borderBottom: 1, borderColor: 'divider', marginBottom: 4 }}
            >
              <Tabs
                value={getCurrentTab(location.pathname, data.id, '/dashboard/threats/threat_actors_individual')}
              >
                <Tab
                  component={Link}
                  to={`/dashboard/threats/threat_actors_individual/${data.id}`}
                  value={`/dashboard/threats/threat_actors_individual/${data.id}`}
                  label={t_i18n('Overview')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/threats/threat_actors_individual/${data.id}/knowledge/overview`}
                  value={`/dashboard/threats/threat_actors_individual/${data.id}/knowledge`}
                  label={t_i18n('Knowledge')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/threats/threat_actors_individual/${data.id}/content`}
                  value={`/dashboard/threats/threat_actors_individual/${data.id}/content`}
                  label={t_i18n('Content')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/threats/threat_actors_individual/${data.id}/analyses`}
                  value={`/dashboard/threats/threat_actors_individual/${data.id}/analyses`}
                  label={t_i18n('Analyses')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/threats/threat_actors_individual/${data.id}/files`}
                  value={`/dashboard/threats/threat_actors_individual/${data.id}/files`}
                  label={t_i18n('Data')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/threats/threat_actors_individual/${data.id}/history`}
                  value={`/dashboard/threats/threat_actors_individual/${data.id}/history`}
                  label={t_i18n('History')}
                />
              </Tabs>
              {isOverview && (
              <StixCoreObjectSimulationResult id={data.id} type="threat" />
              )}
            </Box>
            <Routes>
              <Route
                path="/"
                element={
                  <ThreatActorIndividual data={data} />
                }
              />
              <Route
                path="/knowledge"
                element={
                  <Navigate to={`/dashboard/threats/threat_actors_individual/${data.id}/knowledge/overview`} replace={true} />
                }
              />
              <Route
                path="/knowledge/*"
                element={
                  <ThreatActorIndividualKnowledge threatActorIndividualData={data} />
                }
              />
              <Route
                path="/content/*"
                element={
                  <StixCoreObjectContentRoot
                    stixCoreObject={data}
                  />
                }
              />
              <Route
                path="/analyses"
                element={
                  <StixCoreObjectOrStixCoreRelationshipContainers stixDomainObjectOrStixCoreRelationship={data} />
                }
              />
              <Route
                path="/files"
                element={
                  <FileManager
                    id={threatActorIndividualId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={data}
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
