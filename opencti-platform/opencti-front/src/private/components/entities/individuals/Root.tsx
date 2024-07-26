import React, { useMemo, Suspense, useState } from 'react';
import { Route, Routes, Link, Navigate, useLocation, useParams, useNavigate } from 'react-router-dom';
import { graphql, useSubscription, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import { propOr } from 'ramda';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { RootIndividualQuery } from '@components/entities/individuals/__generated__/RootIndividualQuery.graphql';
import { RootIndicatorSubscription } from '@components/observations/indicators/__generated__/RootIndicatorSubscription.graphql';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import Individual from './Individual';
import IndividualKnowledge from './IndividualKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import IndividualPopover from './IndividualPopover';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import IndividualAnalysis from './IndividualAnalysis';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../../utils/ListParameters';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';
import IndividualEdition from './IndividualEdition';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import useHelper from '../../../../utils/hooks/useHelper';
import CreateRelationshipContextProvider from '../../common/menus/CreateRelationshipContextProvider';
import CreateRelationshipButtonComponent from '../../common/menus/CreateRelationshipButtonComponent';

const subscription = graphql`
  subscription RootIndividualsSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Individual {
        ...Individual_individual
        ...IndividualEditionContainer_individual
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...PictureManagementViewer_entity
    }
  }
`;

const individualQuery = graphql`
  query RootIndividualQuery($id: String!) {
    individual(id: $id) {
      id
      isUser
      entity_type
      name
      x_opencti_aliases
      stixCoreObjectsDistribution(field: "entity_type", operation: count) {
        label
        value
      }
      ...Individual_individual
      ...IndividualKnowledge_individual
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

type RootIndividualProps = {
  individualId: string;
  queryRef: PreloadedQuery<RootIndividualQuery>;
};

const RootIndividual = ({ individualId, queryRef }: RootIndividualProps) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootIndicatorSubscription>>(() => ({
    subscription,
    variables: { id: individualId },
  }), [individualId]);
  const location = useLocation();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const navigate = useNavigate();
  const LOCAL_STORAGE_KEY = `individual-${individualId}`;
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
  useSubscription<RootIndicatorSubscription>(subConfig);

  const {
    individual,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootIndividualQuery>(individualQuery, queryRef);

  const { forceUpdate } = useForceUpdate();

  const link = `/dashboard/entities/individuals/${individualId}/knowledge`;
  let paddingRight = 0;
  if (viewAs === 'knowledge') {
    paddingRight = getPaddingRight(location.pathname, individualId, '/dashboard/entities/individuals');
  }

  return (
    <CreateRelationshipContextProvider>
      {individual ? (
        <>
          <Routes>
            <Route
              path="/knowledge/*"
              element={viewAs === 'knowledge' && (
                <StixCoreObjectKnowledgeBar
                  stixCoreObjectLink={link}
                  availableSections={[
                    'organizations',
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
                  stixCoreObjectsDistribution={individual.stixCoreObjectsDistribution}
                />
              )}
            />
          </Routes>
          <div style={{ paddingRight }}>
            <Breadcrumbs elements={[
              { label: t_i18n('Entities') },
              { label: t_i18n('Individuals'), link: '/dashboard/entities/individuals' },
              { label: individual.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="Individual"
              stixDomainObject={individual}
              isOpenctiAlias={true}
              enableQuickSubscription={true}
              PopoverComponent={<IndividualPopover id={individual.id}/>}
              EditComponent={!individual.isUser && isFABReplaced && (
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <IndividualEdition individualId={individual.id} />
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
                value={getCurrentTab(location.pathname, individual.id, '/dashboard/entities/individuals')}
              >
                <Tab
                  component={Link}
                  to={`/dashboard/entities/individuals/${individual.id}`}
                  value={`/dashboard/entities/individuals/${individual.id}`}
                  label={t_i18n('Overview')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/individuals/${individual.id}/knowledge/overview`}
                  value={`/dashboard/entities/individuals/${individual.id}/knowledge`}
                  label={t_i18n('Knowledge')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/individuals/${individual.id}/content`}
                  value={`/dashboard/entities/individuals/${individual.id}/content`}
                  label={t_i18n('Content')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/individuals/${individual.id}/analyses`}
                  value={`/dashboard/entities/individuals/${individual.id}/analyses`}
                  label={t_i18n('Analyses')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/individuals/${individual.id}/sightings`}
                  value={`/dashboard/entities/individuals/${individual.id}/sightings`}
                  label={t_i18n('Sightings')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/individuals/${individual.id}/files`}
                  value={`/dashboard/entities/individuals/${individual.id}/files`}
                  label={t_i18n('Data')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/individuals/${individual.id}/history`}
                  value={`/dashboard/entities/individuals/${individual.id}/history`}
                  label={t_i18n('History')}
                />
              </Tabs>
            </Box>
            <Routes>
              <Route
                path="/"
                element={
                  <Individual
                    individualData={individual}
                    viewAs={viewAs}
                  />
                }
              />
              <Route
                path="/knowledge"
                element={
                  <Navigate
                    replace={true}
                    to={`/dashboard/entities/individuals/${individualId}/knowledge/overview`}
                  />
                }
              />
              <Route
                path="/knowledge/*"
                element={
                  <div key={forceUpdate}>
                    <IndividualKnowledge
                      individual={individual}
                      viewAs={viewAs}
                    />
                  </div>
                }
              />
              <Route
                path="/content/*"
                element={
                  <StixCoreObjectContentRoot
                    stixCoreObject={individual}
                  />
                }
              />
              <Route
                path="/analyses"
                element={
                  <IndividualAnalysis
                    individual={individual}
                    viewAs={viewAs}
                  />
                }
              />
              <Route
                path="/sightings"
                element={
                  <EntityStixSightingRelationships
                    entityId={individual.id}
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
                    id={individualId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={individual}
                  />
                }
              />
              <Route
                path="/history"
                element={
                  <StixCoreObjectHistory
                    stixCoreObjectId={individualId}
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
  const { individualId } = useParams() as { individualId: string; };
  const queryRef = useQueryLoading<RootIndividualQuery>(individualQuery, {
    id: individualId,
  });

  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootIndividual individualId={individualId} queryRef={queryRef} />
        </Suspense>
      )}
    </>
  );
};

export default Root;
