import { useMemo, Suspense } from 'react';
import { Route, Routes, Navigate, useLocation, useParams } from 'react-router-dom';
import { graphql, useSubscription, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import { RootPositionQuery } from '@components/locations/positions/__generated__/RootPositionQuery.graphql';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import { RootPositionsSubscription } from '@components/locations/positions/__generated__/RootPositionsSubscription.graphql';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import StixDomainObjectTabsBox from '@components/common/stix_domain_objects/StixDomainObjectTabsBox';
import StixCoreRelationshipCreationFromEntityHeader from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntityHeader';
import CreateRelationshipContextProvider from '@components/common/stix_core_relationships/CreateRelationshipContextProvider';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import Position from './Position';
import PositionKnowledge from './PositionKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getPaddingRight } from '../../../../utils/utils';
import PositionEdition from './PositionEdition';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import PositionDeletion from './PositionDeletion';
import { useEntityLabelResolver } from '../../../../utils/hooks/useEntityLabel';

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
      draftVersion {
        draft_id
        draft_operation
      }
      entity_type
      name
      x_opencti_aliases
      currentUserAccessRight
      ...StixCoreRelationshipCreationFromEntityHeader_stixCoreObject
      ...StixCoreObjectKnowledgeBar_stixCoreObject
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
  const { t_i18n } = useFormatter();
  const entityLabel = useEntityLabelResolver();
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
              element={(
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
                  data={position}
                />
              )}
            />
          </Routes>
          <div style={{ paddingRight }}>
            <Breadcrumbs elements={[
              { label: t_i18n('Locations') },
              { label: entityLabel('Position', t_i18n('Positions')), link: '/dashboard/locations/positions' },
              { label: position.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="Position"
              disableSharing={true}
              stixDomainObject={position}
              EditComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <PositionEdition positionId={position.id} />
                </Security>
              )}
              RelateComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <StixCoreRelationshipCreationFromEntityHeader
                    data={position}
                  />
                </Security>
              )}
              DeleteComponent={({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => (
                <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                  <PositionDeletion positionId={position.id} isOpen={isOpen} handleClose={onClose} />
                </Security>
              )}
              enableQuickSubscription={true}
              isOpenctiAlias={true}
              redirectToContent={true}
              enableEnrollPlaybook={true}
            />
            <StixDomainObjectTabsBox
              basePath="/dashboard/locations/positions"
              entity={position}
              tabs={[
                'overview',
                'knowledge-overview',
                'content',
                'analyses',
                'sightings',
                'files',
                'history',
              ]}
            />
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
                element={(
                  <div key={forceUpdate}>
                    <PositionKnowledge positionData={position} />
                  </div>
                )}
              />
              <Route
                path="/content/*"
                element={(
                  <StixCoreObjectContentRoot
                    stixCoreObject={position}
                  />
                )}
              />
              <Route
                path="/analyses"
                element={
                  <StixCoreObjectOrStixCoreRelationshipContainers stixDomainObjectOrStixCoreRelationship={position} />
                }
              />
              <Route
                path="/sightings"
                element={(
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
                )}
              />
              <Route
                path="/files"
                element={(
                  <FileManager
                    id={positionId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={position}
                  />
                )}
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
  const { positionId } = useParams() as { positionId: string };
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
