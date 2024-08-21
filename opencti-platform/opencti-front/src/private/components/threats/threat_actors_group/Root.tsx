import React, { Suspense, useMemo } from 'react';
import { Route, Routes, Link, Navigate, useLocation, useParams } from 'react-router-dom';
import { graphql, useSubscription, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import { RootThreatActorGroupQuery } from '@components/threats/threat_actors_group/__generated__/RootThreatActorGroupQuery.graphql';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import { RootThreatActorsGroupSubscription } from '@components/threats/threat_actors_group/__generated__/RootThreatActorsGroupSubscription.graphql';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import StixCoreObjectSimulationResult from '../../common/stix_core_objects/StixCoreObjectSimulationResult';
import ThreatActorGroup from './ThreatActorGroup';
import ThreatActorGroupKnowledge from './ThreatActorGroupKnowledge';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import FileManager from '../../common/files/FileManager';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import ThreatActorGroupPopover from './ThreatActorGroupPopover';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';

const subscription = graphql`
  subscription RootThreatActorsGroupSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on ThreatActor {
        ...ThreatActorGroup_ThreatActorGroup
        ...ThreatActorGroupEditionContainer_ThreatActorGroup
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...PictureManagementViewer_entity
    }
  }
`;

const ThreatActorGroupQuery = graphql`
  query RootThreatActorGroupQuery($id: String!) {
    threatActorGroup(id: $id) {
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
      ...ThreatActorGroup_ThreatActorGroup
      ...ThreatActorGroupKnowledge_ThreatActorGroup
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...PictureManagementViewer_entity
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

type RootThreatActorGroupProps = {
  threatActorGroupId: string;
  queryRef: PreloadedQuery<RootThreatActorGroupQuery>
};

const RootThreatActorGroup = ({ queryRef, threatActorGroupId }: RootThreatActorGroupProps) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootThreatActorsGroupSubscription>>(() => ({
    subscription,
    variables: { id: threatActorGroupId },
  }), [threatActorGroupId]);

  const location = useLocation();
  const { t_i18n } = useFormatter();
  useSubscription<RootThreatActorsGroupSubscription>(subConfig);

  const {
    threatActorGroup,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootThreatActorGroupQuery>(ThreatActorGroupQuery, queryRef);

  const isOverview = location.pathname === `/dashboard/threats/threat_actors_group/${threatActorGroupId}`;
  const paddingRight = getPaddingRight(location.pathname, threatActorGroupId, '/dashboard/threats/threat_actors_group');
  const link = `/dashboard/threats/threat_actors_group/${threatActorGroupId}/knowledge`;
  return (
    <>
      {threatActorGroup ? (
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
                  ]}
                  stixCoreObjectsDistribution={threatActorGroup.stixCoreObjectsDistribution}
                />
              }
            />
          </Routes>
          <div style={{ paddingRight }}>
            <Breadcrumbs variant="object" elements={[
              { label: t_i18n('Threats') },
              { label: t_i18n('Threat actors (group)'), link: '/dashboard/threats/threat_actors_group' },
              { label: threatActorGroup.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="Threat-Actor-Group"
              stixDomainObject={threatActorGroup}
              PopoverComponent={<ThreatActorGroupPopover />}
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
                value={getCurrentTab(location.pathname, threatActorGroup.id, '/dashboard/threats/threat_actors_group')}
              >
                <Tab
                  component={Link}
                  to={`/dashboard/threats/threat_actors_group/${threatActorGroup.id}`}
                  value={`/dashboard/threats/threat_actors_group/${threatActorGroup.id}`}
                  label={t_i18n('Overview')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/threats/threat_actors_group/${threatActorGroup.id}/knowledge/overview`}
                  value={`/dashboard/threats/threat_actors_group/${threatActorGroup.id}/knowledge`}
                  label={t_i18n('Knowledge')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/threats/threat_actors_group/${threatActorGroup.id}/content`}
                  value={`/dashboard/threats/threat_actors_group/${threatActorGroup.id}/content`}
                  label={t_i18n('Content')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/threats/threat_actors_group/${threatActorGroup.id}/analyses`}
                  value={`/dashboard/threats/threat_actors_group/${threatActorGroup.id}/analyses`}
                  label={t_i18n('Analyses')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/threats/threat_actors_group/${threatActorGroup.id}/files`}
                  value={`/dashboard/threats/threat_actors_group/${threatActorGroup.id}/files`}
                  label={t_i18n('Data')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/threats/threat_actors_group/${threatActorGroup.id}/history`}
                  value={`/dashboard/threats/threat_actors_group/${threatActorGroup.id}/history`}
                  label={t_i18n('History')}
                />
              </Tabs>
              {isOverview && (
                <StixCoreObjectSimulationResult id={threatActorGroup.id} type="threat" />
              )}
            </Box>
            <Routes>
              <Route
                path="/"
                element={
                  <ThreatActorGroup threatActorGroupData={threatActorGroup} />
                }
              />
              <Route
                path="/knowledge"
                element={
                  <Navigate to={`/dashboard/threats/threat_actors_group/${threatActorGroupId}/knowledge/overview`} replace={true} />
                }
              />
              <Route
                path="/knowledge/*"
                element={<ThreatActorGroupKnowledge threatActorGroup={threatActorGroup} />}
              />
              <Route
                path="/content/*"
                element={
                  <StixCoreObjectContentRoot
                    stixCoreObject={threatActorGroup}
                  />
                }
              />
              <Route
                path="/analyses"
                element={
                  <StixCoreObjectOrStixCoreRelationshipContainers stixDomainObjectOrStixCoreRelationship={threatActorGroup} />
                }
              />
              <Route
                path="/files"
                element={
                  <FileManager
                    id={threatActorGroupId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={threatActorGroup}
                  />
                }
              />
              <Route
                path="/history"
                element={
                  <StixCoreObjectHistory stixCoreObjectId={threatActorGroupId} />
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
  const { threatActorGroupId } = useParams() as { threatActorGroupId: string; };
  const queryRef = useQueryLoading<RootThreatActorGroupQuery>(ThreatActorGroupQuery, {
    id: threatActorGroupId,
  });

  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootThreatActorGroup queryRef={queryRef} threatActorGroupId={threatActorGroupId} />
        </Suspense>
      )}
    </>
  );
};

export default Root;
