import React, { useMemo, Suspense } from 'react';
import { Route, Routes, Link, Navigate, useLocation, useParams } from 'react-router-dom';
import { graphql, useSubscription, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { RootPositionQuery } from '@components/locations/positions/__generated__/RootPositionQuery.graphql';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import { RootPositionsSubscription } from '@components/locations/positions/__generated__/RootPositionsSubscription.graphql';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import Position from './Position';
import PositionKnowledge from './PositionKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import PositionPopover from './PositionPopover';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';
import PositionEdition from './PositionEdition';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import useHelper from '../../../../utils/hooks/useHelper';
import CreateRelationshipContextProvider from '../../common/menus/CreateRelationshipContextProvider';
import CreateRelationshipButtonComponent from '../../common/menus/CreateRelationshipButtonComponent';

const subscription = graphql`
  subscription RootPositionsSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Position {
        ...Position_position
        ...PositionEditionContainer_position
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const positionQuery = graphql`
  query RootPositionQuery($id: String!) {
    position(id: $id) {
      id
      entity_type
      name
      x_opencti_aliases
      stixCoreObjectsDistribution(field: "entity_type", operation: count) {
        label
        value
      }
      ...Position_position
      ...PositionKnowledge_position
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

type RootPositionProps = {
  positionId: string;
  queryRef: PreloadedQuery<RootPositionQuery>;
};

const RootPosition = ({ positionId, queryRef }: RootPositionProps) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootPositionsSubscription>>(() => ({
    subscription,
    variables: { id: positionId },
  }), [positionId]);

  const location = useLocation();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const { t_i18n } = useFormatter();
  useSubscription<RootPositionsSubscription>(subConfig);

  const {
    position,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootPositionQuery>(positionQuery, queryRef);

  const { forceUpdate } = useForceUpdate();

  const link = `/dashboard/locations/positions/${positionId}/knowledge`;
  const paddingRight = getPaddingRight(location.pathname, positionId, '/dashboard/locations/positions');

  return (
    <CreateRelationshipContextProvider>
      {position ? (
        <>
          <Routes>
            <Route
              path="/knowledge/*"
              element={
                <StixCoreObjectKnowledgeBar
                  stixCoreObjectLink={link}
                  availableSections={[
                    'organizations',
                    'regions',
                    'countries',
                    'areas',
                    'cities',
                    'threat_actors',
                    'intrusion_sets',
                    'campaigns',
                    'incidents',
                    'malwares',
                    'attack_patterns',
                    'tools',
                    'observables',
                  ]}
                  stixCoreObjectsDistribution={position.stixCoreObjectsDistribution}
                />
              }
            />
          </Routes>
          <div style={{ paddingRight }}>
            <Breadcrumbs elements={[
              { label: t_i18n('Locations') },
              { label: t_i18n('Positions'), link: '/dashboard/locations/positions' },
              { label: position.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="Position"
              disableSharing={true}
              stixDomainObject={position}
              PopoverComponent={<PositionPopover id={position.id} />}
              EditComponent={isFABReplaced && (
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <PositionEdition positionId={position.id} />
                </Security>
              )}
              RelateComponent={CreateRelationshipButtonComponent}
              enableQuickSubscription={true}
              isOpenctiAlias={true}
            />
            <Box
              sx={{
                borderBottom: 1,
                borderColor: 'divider',
                marginBottom: 3,
              }}
            >
              <Tabs
                value={getCurrentTab(location.pathname, position.id, '/dashboard/locations/positions')}
              >
                <Tab
                  component={Link}
                  to={`/dashboard/locations/positions/${position.id}`}
                  value={`/dashboard/locations/positions/${position.id}`}
                  label={t_i18n('Overview')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/locations/positions/${position.id}/knowledge/overview`}
                  value={`/dashboard/locations/positions/${position.id}/knowledge`}
                  label={t_i18n('Knowledge')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/locations/positions/${position.id}/content`}
                  value={`/dashboard/locations/positions/${position.id}/content`}
                  label={t_i18n('Content')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/locations/positions/${position.id}/analyses`}
                  value={`/dashboard/locations/positions/${position.id}/analyses`}
                  label={t_i18n('Analyses')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/locations/positions/${position.id}/sightings`}
                  value={`/dashboard/locations/positions/${position.id}/sightings`}
                  label={t_i18n('Sightings')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/locations/positions/${position.id}/files`}
                  value={`/dashboard/locations/positions/${position.id}/files`}
                  label={t_i18n('Data')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/locations/positions/${position.id}/history`}
                  value={`/dashboard/locations/positions/${position.id}/history`}
                  label={t_i18n('History')}
                />
              </Tabs>
            </Box>
            <Routes>
              <Route
                path="/"
                element={
                  <Position position={position} />
                }
              />
              <Route
                path="/knowledge"
                element={
                  <Navigate to={`/dashboard/locations/positions/${positionId}/knowledge/overview`} replace={true} />
                }
              />
              <Route
                path="/knowledge/*"
                element={
                  <div key={forceUpdate}>
                    <PositionKnowledge position={position} />
                  </div>
                }
              />
              <Route
                path="/content/*"
                element={
                  <StixCoreObjectContentRoot
                    stixCoreObject={position}
                  />
                }
              />
              <Route
                path="/analyses"
                element={
                  <StixCoreObjectOrStixCoreRelationshipContainers stixDomainObjectOrStixCoreRelationship={position} />
                }
              />
              <Route
                path="/sightings"
                element={
                  <EntityStixSightingRelationships
                    entityId={position.id}
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
                    id={positionId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={position}
                  />
                }
              />
              <Route
                path="/history"
                element={
                  <StixCoreObjectHistory stixCoreObjectId={positionId} />
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
  const { positionId } = useParams() as { positionId: string; };
  const queryRef = useQueryLoading<RootPositionQuery>(positionQuery, {
    id: positionId,
  });

  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootPosition positionId={positionId} queryRef={queryRef} />
        </Suspense>
      )}
    </>
  );
};

export default Root;
