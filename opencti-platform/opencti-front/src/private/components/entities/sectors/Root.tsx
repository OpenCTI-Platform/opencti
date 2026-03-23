import { Suspense, useMemo } from 'react';
import { Route, Routes, useLocation, useParams } from 'react-router-dom';
import { graphql, PreloadedQuery, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import { RootSectorQuery } from '@components/entities/sectors/__generated__/RootSectorQuery.graphql';
import { RootSectorSubscription } from '@components/entities/sectors/__generated__/RootSectorSubscription.graphql';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import AIInsights from '@components/common/ai/AIInsights';
import StixDomainObjectTabsBox from '@components/common/stix_domain_objects/StixDomainObjectTabsBox';
import StixCoreRelationshipCreationFromEntityHeader from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntityHeader';
import CreateRelationshipContextProvider from '@components/common/stix_core_relationships/CreateRelationshipContextProvider';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import Sector from './Sector';
import SectorKnowledge from './SectorKnowledge';
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
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import SectorEdition from './SectorEdition';
import SectorDeletion from './SectorDeletion';

const subscription = graphql`
  subscription RootSectorSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Sector {
        ...Sector_sector
        ...SectorEditionContainer_sector
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const sectorQuery = graphql`
  query RootSectorQuery($id: String!) {
    sector(id: $id) {
      id
      draftVersion {
        draft_id
        draft_operation
      }
      standard_id
      entity_type
      name
      x_opencti_aliases
      x_opencti_graph_data
      currentUserAccessRight
      ...StixCoreRelationshipCreationFromEntityHeader_stixCoreObject
      ...StixCoreObjectKnowledgeBar_stixCoreObject
      ...Sector_sector
      ...SectorKnowledge_sector
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

type RootSectorProps = {
  sectorId: string;
  queryRef: PreloadedQuery<RootSectorQuery>;
};

const RootSector = ({ sectorId, queryRef }: RootSectorProps) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootSectorSubscription>>(() => ({
    subscription,
    variables: { id: sectorId },
  }), [sectorId]);

  const location = useLocation();
  const { t_i18n } = useFormatter();
  useSubscription<RootSectorSubscription>(subConfig);

  const {
    sector,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootSectorQuery>(sectorQuery, queryRef);

  const { forceUpdate } = useForceUpdate();

  const isOverview = location.pathname === `/dashboard/entities/sectors/${sectorId}`;
  const paddingRight = getPaddingRight(location.pathname, sectorId, '/dashboard/entities/sectors');
  const link = `/dashboard/entities/sectors/${sectorId}/knowledge`;
  return (
    <CreateRelationshipContextProvider>
      {sector ? (
        <>
          <Routes>
            <Route
              path="/knowledge/*"
              element={(
                <StixCoreObjectKnowledgeBar
                  stixCoreObjectLink={link}
                  availableSections={[
                    'organizations',
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
                  data={sector}
                />
              )}
            />
          </Routes>
          <div style={{ paddingRight }}>
            <Breadcrumbs elements={[
              { label: t_i18n('Entities') },
              { label: t_i18n('Sectors'), link: '/dashboard/entities/sectors' },
              { label: sector.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="Sector"
              disableSharing={true}
              stixDomainObject={sector}
              isOpenctiAlias={true}
              enableQuickSubscription={true}
              EditComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <SectorEdition sectorId={sector.id} />
                </Security>
              )}
              RelateComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <StixCoreRelationshipCreationFromEntityHeader
                    data={sector}
                  />
                </Security>
              )}
              DeleteComponent={({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => (
                <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                  <SectorDeletion id={sector.id} isOpen={isOpen} handleClose={onClose} />
                </Security>
              )}
              redirectToContent={true}
              enableEnrollPlaybook={true}
            />
            <StixDomainObjectTabsBox
              basePath="/dashboard/entities/sectors"
              entity={sector}
              tabs={[
                'overview',
                'knowledge',
                'content',
                'analyses',
                'sightings',
                'files',
                'history',
              ]}
              extraActions={isOverview && <AIInsights id={sector.id} />}
            />
            <Routes>
              <Route
                path="/"
                element={(
                  <Sector sectorData={sector} />
                )}
              />
              <Route
                path="/knowledge/*"
                element={(
                  <div key={forceUpdate}>
                    <SectorKnowledge sectorData={sector} />
                  </div>
                )}
              />
              <Route
                path="/content/*"
                element={(
                  <StixCoreObjectContentRoot
                    stixCoreObject={sector}
                  />
                )}
              />
              <Route
                path="/analyses"
                element={(
                  <StixCoreObjectOrStixCoreRelationshipContainers
                    stixDomainObjectOrStixCoreRelationship={sector}
                  />
                )}
              />
              <Route
                path="/sightings"
                element={(
                  <EntityStixSightingRelationships
                    entityId={sector.id}
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
                    id={sectorId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={sector}
                  />
                )}
              />
              <Route
                path="/history"
                element={(
                  <StixCoreObjectHistory
                    stixCoreObjectId={sectorId}
                  />
                )}
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
  const { sectorId } = useParams() as { sectorId: string };
  const queryRef = useQueryLoading<RootSectorQuery>(sectorQuery, {
    id: sectorId,
  });

  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootSector sectorId={sectorId} queryRef={queryRef} />
        </Suspense>
      )}
    </>
  );
};

export default Root;
