import React, { useMemo, Suspense, useState } from 'react';
import { Route, Routes, Link, Navigate, useLocation, useParams, useNavigate } from 'react-router-dom';
import { graphql, useSubscription, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import { propOr } from 'ramda';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { RootSystemQuery } from '@components/entities/systems/__generated__/RootSystemQuery.graphql';
import { RootSystemsSubscription } from '@components/entities/systems/__generated__/RootSystemsSubscription.graphql';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import System from './System';
import SystemKnowledge from './SystemKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import SystemPopover from './SystemPopover';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import SystemAnalysis from './SystemAnalysis';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../../utils/ListParameters';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import SystemEdition from './SystemEdition';
import useHelper from '../../../../utils/hooks/useHelper';
import CreateRelationshipContextProvider from '../../common/menus/CreateRelationshipContextProvider';
import CreateRelationshipButtonComponent from '../../common/menus/CreateRelationshipButtonComponent';

const subscription = graphql`
  subscription RootSystemsSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on System {
        ...System_system
        ...SystemEditionContainer_system
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const systemQuery = graphql`
  query RootSystemQuery($id: String!) {
    system(id: $id) {
      id
      entity_type
      name
      x_opencti_aliases
      stixCoreObjectsDistribution(field: "entity_type", operation: count) {
        label
        value
      }
      ...System_system
      ...SystemKnowledge_system
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

type RootSystemProps = {
  systemId: string;
  queryRef: PreloadedQuery<RootSystemQuery>;
};

const RootSystem = ({ systemId, queryRef }: RootSystemProps) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootSystemsSubscription>>(() => ({
    subscription,
    variables: { id: systemId },
  }), [systemId]);
  const location = useLocation();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const navigate = useNavigate();
  const LOCAL_STORAGE_KEY = `system-${systemId}`;
  const params = buildViewParamsFromUrlAndStorage(
    navigate,
    location,
    LOCAL_STORAGE_KEY,
  );

  const [viewAs, setViewAs] = useState<string>(propOr('knowledge', 'viewAs', params));

  const saveView = () => {
    saveViewParameters(
      navigate,
      location,
      LOCAL_STORAGE_KEY,
      viewAs,
    );
  };

  const handleChangeViewAs = (event: React.ChangeEvent<{ value: string }>) => {
    setViewAs(event.target.value);
    saveView();
  };

  const { t_i18n } = useFormatter();
  useSubscription<RootSystemsSubscription>(subConfig);

  const {
    system,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootSystemQuery>(systemQuery, queryRef);

  const { forceUpdate } = useForceUpdate();

  const link = `/dashboard/entities/systems/${systemId}/knowledge`;
  const paddingRight = getPaddingRight(location.pathname, systemId, '/dashboard/entities/systems');
  return (
    <CreateRelationshipContextProvider>
      {system ? (
        <>
          <Routes>
            <Route
              path="/knowledge/*"
              element={viewAs === 'knowledge' && (
                <StixCoreObjectKnowledgeBar
                  stixCoreObjectLink={link}
                  availableSections={[
                    'systems',
                    'systems',
                    'threats',
                    'threat_actors',
                    'intrusion_sets',
                    'campaigns',
                    'incidents',
                    'malwares',
                    'attack_patterns',
                    'tools',
                    'observables',
                    'vulnerabilities',
                  ]}
                  stixCoreObjectsDistribution={system.stixCoreObjectsDistribution}
                />
              )}
            />
          </Routes>
          <div style={{ paddingRight }}>
            <Breadcrumbs elements={[
              { label: t_i18n('Entities') },
              { label: t_i18n('Systems'), link: '/dashboard/entities/systems' },
              { label: system.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="System"
              stixDomainObject={system}
              isOpenctiAlias={true}
              enableQuickSubscription={true}
              enableEnricher={true}
              PopoverComponent={<SystemPopover id={system.id}/>}
              EditComponent={isFABReplaced && (
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <SystemEdition systemId={system.id} />
                </Security>
              )}
              RelateComponent={CreateRelationshipButtonComponent}
              onViewAs={handleChangeViewAs}
              viewAs={viewAs}
            />
            <Box
              sx={{
                borderBottom: 1,
                borderColor: 'divider',
                marginBottom: 3,
              }}
            >
              <Tabs
                value={getCurrentTab(location.pathname, system.id, '/dashboard/entities/systems')}
              >
                <Tab
                  component={Link}
                  to={`/dashboard/entities/systems/${system.id}`}
                  value={`/dashboard/entities/systems/${system.id}`}
                  label={t_i18n('Overview')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/systems/${system.id}/knowledge/overview`}
                  value={`/dashboard/entities/systems/${system.id}/knowledge`}
                  label={t_i18n('Knowledge')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/systems/${system.id}/content`}
                  value={`/dashboard/entities/systems/${system.id}/content`}
                  label={t_i18n('Content')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/systems/${system.id}/analyses`}
                  value={`/dashboard/entities/systems/${system.id}/analyses`}
                  label={t_i18n('Analyses')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/systems/${system.id}/sightings`}
                  value={`/dashboard/entities/systems/${system.id}/sightings`}
                  label={t_i18n('Sightings')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/systems/${system.id}/files`}
                  value={`/dashboard/entities/systems/${system.id}/files`}
                  label={t_i18n('Data')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/systems/${system.id}/history`}
                  value={`/dashboard/entities/systems/${system.id}/history`}
                  label={t_i18n('History')}
                />
              </Tabs>
            </Box>
            <Routes>
              <Route
                path="/"
                element={
                  <System
                    systemData={system}
                    viewAs={viewAs}
                  />
                }
              />
              <Route
                path="/knowledge"
                element={
                  <Navigate
                    replace={true}
                    to={`/dashboard/entities/systems/${systemId}/knowledge/overview`}
                  />
                }
              />
              <Route
                path="/knowledge/*"
                element={
                  <div key={forceUpdate}>
                    <SystemKnowledge
                      system={system}
                      viewAs={viewAs}
                    />
                  </div>
                }
              />
              <Route
                path="/content/*"
                element={
                  <StixCoreObjectContentRoot
                    stixCoreObject={system}
                  />
                }
              />
              <Route
                path="/analyses/*"
                element={
                  <SystemAnalysis
                    system={system}
                    viewAs={viewAs}
                  />
                }
              />
              <Route
                path="/sightings"
                element={
                  <EntityStixSightingRelationships
                    entityId={system.id}
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
                }
              />
              <Route
                path="/files"
                element={
                  <FileManager
                    id={systemId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={system}
                  />
                }
              />
              <Route
                path="/history"
                element={
                  <StixCoreObjectHistory
                    stixCoreObjectId={systemId}
                  />
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
  const { systemId } = useParams() as { systemId: string; };
  const queryRef = useQueryLoading<RootSystemQuery>(systemQuery, {
    id: systemId,
  });

  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootSystem systemId={systemId} queryRef={queryRef} />
        </Suspense>
      )}
    </>
  );
};

export default Root;
