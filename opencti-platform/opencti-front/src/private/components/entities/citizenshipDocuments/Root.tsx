import React, { useMemo, Suspense, useState } from 'react';
import { Route, Routes, useLocation, useParams, useNavigate } from 'react-router';
import { graphql, useSubscription, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import { propOr } from 'ramda';
import { RootCitizenshipDocumentQuery } from '@components/entities/CitizenshipDocument/__generated__/RootCitizenshipDocumentQuery.graphql';
import { RootIndicatorSubscription } from '@components/observations/indicators/__generated__/RootIndicatorSubscription.graphql';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import StixDomainObjectMain from '@components/common/stix_domain_objects/StixDomainObjectMain';
import CreateRelationshipContextProvider from '@components/common/stix_core_relationships/CreateRelationshipContextProvider';
import StixCoreRelationshipCreationFromEntityHeader from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntityHeader';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import CitizenshipDocument from './CitizenshipDocument';
import CitizenshipDocumentKnowledge from './CitizenshipDocumentKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import CitizenshipDocumentAnalysis from './CitizenshipDocumentAnalysis';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../../utils/ListParameters';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getPaddingRight } from '../../../../utils/utils';
import CitizenshipDocumentEdition from './CitizenshipDocumentEdition';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import CitizenshipDocumentDeletion from './CitizenshipDocumentDeletion';
import { PATH_CITIZENSHIP_DOCUMENT, PATH_CITIZENSHIP_DOCUMENTS } from '@components/common/routes/paths';

const subscription = graphql`
  subscription RootCitizenshipDocumentsSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on CitizenshipDocument {
        ...CitizenshipDocument_citizenshipDocument
        ...CitizenshipDocumentEditionContainer_citizenshipDocument
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...PictureManagementViewer_entity
    }
  }
`;

const citizenshipDocumentQuery = graphql`
  query RootCitizenshipDocumentQuery($id: String!) {
    citizenshipDocument(id: $id) {
      id
      draftVersion {
        draft_id
        draft_operation
      }
      isUser
      entity_type
      name
      x_opencti_aliases
      currentUserAccessRight
      ...StixCoreRelationshipCreationFromEntityHeader_stixCoreObject
      ...StixCoreObjectKnowledgeBar_stixCoreObject
      ...CitizenshipDocument_citizenshipDocument
      ...CitizenshipDocumentKnowledge_citizenshipDocument
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...PictureManagementViewer_entity
      ...StixCoreObjectContent_stixCoreObject
      ...StixCoreObjectSharingListFragment
    }
    connectorsForImport {
      ...FileManager_connectorsImport
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
  }
`;

type RootCitizenshipDocumentProps = {
  citizenshipDocumentId: string;
  queryRef: PreloadedQuery<RootCitizenshipDocumentQuery>;
};

const RootCitizenshipDocument = ({ citizenshipDocumentId, queryRef }: RootCitizenshipDocumentProps) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootIndicatorSubscription>>(() => ({
    subscription,
    variables: { id: citizenshipDocumentId },
  }), [citizenshipDocumentId]);
  const location = useLocation();

  const navigate = useNavigate();
  const LOCAL_STORAGE_KEY = `citizenshipDocument-${citizenshipDocumentId}`;
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
    citizenshipDocument,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootCitizenshipDocumentQuery>(citizenshipDocumentQuery, queryRef);

  const { forceUpdate } = useForceUpdate();

  const basePath = PATH_CITIZENSHIP_DOCUMENT(citizenshipDocumentId);
  const link = `${basePath}/knowledge`;
  let paddingRight = 0;
  if (viewAs === 'knowledge') {
    paddingRight = getPaddingRight(location.pathname, basePath);
  }

  return (
    <CreateRelationshipContextProvider>
      {citizenshipDocument ? (
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
                  data={citizenshipDocument}
                />
              )}
            />
          </Routes>
          <div style={{ paddingRight }}>
            <Breadcrumbs elements={[
              { label: t_i18n('Entities') },
              { label: t_i18n('Citizenship Documents'), link: PATH_CITIZENSHIP_DOCUMENTS },
              { label: citizenshipDocument.name, current: true },
            ]}
            />
            {/* TODO: Lookinto thw isUser, do we need it? */ }
            <StixDomainObjectHeader
              entityType="Citizenship-Document"
              stixDomainObject={citizenshipDocument}
              isOpenctiAlias={true}
              enableQuickSubscription={true}
              EditComponent={!citizenshipDocument.isUser && (
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <CitizenshipDocumentEdition citizenshipDocumentId={citizenshipDocument.id} />
                </Security>
              )}
              RelateComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <StixCoreRelationshipCreationFromEntityHeader
                    data={citizenshipDocument}
                  />
                </Security>
              )}
              DeleteComponent={({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => (
                <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                  <CitizenshipDocumentDeletion id={citizenshipDocument.id} isOpen={isOpen} handleClose={onClose} />
                </Security>
              )}
              onViewAs={handleChangeViewAs}
              viewAs={viewAs}
              redirectToContent={true}
              disableSharing={citizenshipDocument.isUser}
              enableEnrollPlaybook={true}
            />
            <StixDomainObjectMain
              entity={citizenshipDocument}
              basePath={basePath}
              pages={{
                overview: (
                  <CitizenshipDocument
                    citizenshipDocumentData={citizenshipDocument}
                    viewAs={viewAs}
                  />
                ),
                knowledge: (
                  <div key={forceUpdate}>
                    <CitizenshipDocumentKnowledge
                      citizenshipDocumentData={citizenshipDocument}
                      viewAs={viewAs}
                    />
                  </div>
                ),
                content: (
                  <StixCoreObjectContentRoot
                    stixCoreObject={citizenshipDocument}
                  />
                ),
                analyses: (
                  <CitizenshipDocumentAnalysis
                    citizenshipDocument={citizenshipDocument}
                    viewAs={viewAs}
                  />
                ),
                sightings: (
                  <EntityStixSightingRelationships
                    entityId={citizenshipDocument.id}
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
                      'CitizenshipDocument',
                    ]}
                  />
                ),
                files: (
                  <FileManager
                    id={citizenshipDocumentId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={citizenshipDocument}
                  />
                ),
                history: (
                  <StixCoreObjectHistory
                    stixCoreObjectId={citizenshipDocumentId}
                  />
                ),
              }}
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
  const { citizenshipDocumentId } = useParams() as { citizenshipDocumentId: string };
  const queryRef = useQueryLoading<RootCitizenshipDocumentQuery>(citizenshipDocumentQuery, {
    id: citizenshipDocumentId,
  });

  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootCitizenshipDocument citizenshipDocumentId={citizenshipDocumentId} queryRef={queryRef} />
        </Suspense>
      )}
    </>
  );
};

export default Root;
