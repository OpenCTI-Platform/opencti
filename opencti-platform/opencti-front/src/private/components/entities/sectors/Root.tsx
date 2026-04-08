import { Suspense, useMemo } from 'react';
import { Route, Routes, useLocation, useParams } from 'react-router-dom';
import { graphql, PreloadedQuery, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import { RootSectorQuery } from '@components/entities/sectors/__generated__/RootSectorQuery.graphql';
import { RootSectorSubscription } from '@components/entities/sectors/__generated__/RootSectorSubscription.graphql';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import AIInsights from '@components/common/ai/AIInsights';
import StixCoreRelationshipCreationFromEntityHeader from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntityHeader';
import StixDomainObjectMain from '@components/common/stix_domain_objects/StixDomainObjectMain';
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
import { PATH_SECTOR, PATH_SECTORS } from '@components/common/routes/paths';

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

  const basePath = PATH_SECTOR(sectorId);
  const isOverview = location.pathname === basePath;
  const paddingRight = getPaddingRight(location.pathname, basePath);
  const link = `${basePath}/knowledge`;
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
              { label: t_i18n('Sectors'), link: PATH_SECTORS },
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
            <StixDomainObjectMain
              entityType="Sector"
              basePath={basePath}
              pages={{
                overview:
                  <Sector sectorData={sector} />,
                knowledge: (
                  <div key={forceUpdate}>
                    <SectorKnowledge sectorData={sector} />
                  </div>
                ),
                content: (
                  <StixCoreObjectContentRoot
                    stixCoreObject={sector}
                  />
                ),
                analyses: (
                  <StixCoreObjectOrStixCoreRelationshipContainers
                    stixDomainObjectOrStixCoreRelationship={sector}
                  />
                ),
                sightings: (
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
                ),
                files: (
                  <FileManager
                    id={sectorId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={sector}
                  />
                ),
                history: (
                  <StixCoreObjectHistory
                    stixCoreObjectId={sectorId}
                  />
                ),
              }}
              extraActions={isOverview && <AIInsights id={sector.id} />}
            />
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
