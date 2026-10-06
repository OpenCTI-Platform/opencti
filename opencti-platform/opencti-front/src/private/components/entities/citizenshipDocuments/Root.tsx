import { useMemo, Suspense } from 'react';
import { Route, Routes, useLocation, useParams } from 'react-router';
import { graphql, useSubscription, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import { RootCitizenshipDocumentSubscription } from '@components/entities/citizenshipDocuments/__generated__/RootCitizenshipDocumentSubscription.graphql';
import { RootCitizenshipDocumentQuery } from '@components/entities/citizenshipDocuments/__generated__/RootCitizenshipDocumentQuery.graphql';
import CitizenshipDocumentKnowledge from '@components/entities/citizenshipDocuments/CitizenshipDocumentKnowledge';
import CitizenshipDocumentEdition from '@components/entities/citizenshipDocuments/CitizenshipDocumentEdition';
import CitizenshipDocumentAnalysis from '@components/entities/citizenshipDocuments/CitizenshipDocumentAnalysis';
import CreateRelationshipContextProvider from '@components/common/stix_core_relationships/CreateRelationshipContextProvider';
import StixCoreRelationshipCreationFromEntityHeader from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntityHeader';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import CitizenshipDocument from './CitizenshipDocument';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixDomainObjectMain from '@components/common/stix_domain_objects/StixDomainObjectMain';
import FileManager from '../../common/files/FileManager';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getPaddingRight } from '../../../../utils/utils';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import CitizenshipDocumentDeletion from './CitizenshipDocumentDeletion';
import { PATH_CITIZENSHIP_DOCUMENT, PATH_CITIZENSHIP_DOCUMENTS } from '@components/common/routes/paths';

const subscription = graphql`
  subscription RootCitizenshipDocumentSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on CitizenshipDocument {
        ...CitizenshipDocument_citizenshipDocument
        ...CitizenshipDocumentEditionContainer_citizenshipDocument
        ...CitizenshipDocumentDetails_citizenshipDocument
        ...CitizenshipDocumentAnalysis_citizenshipDocument
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
      standard_id
      entity_type
      name
      x_opencti_aliases
      x_opencti_citizenship_document_type
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
      ...CitizenshipDocumentAnalysis_citizenshipDocument
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
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootCitizenshipDocumentSubscription>>(() => ({
    subscription,
    variables: { id: citizenshipDocumentId },
  }), [citizenshipDocumentId]);
  const location = useLocation();

  const { t_i18n } = useFormatter();
  useSubscription<RootCitizenshipDocumentSubscription>(subConfig);

  const {
    citizenshipDocument,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootCitizenshipDocumentQuery>(citizenshipDocumentQuery, queryRef);

  const { forceUpdate } = useForceUpdate();

  const basePath = PATH_CITIZENSHIP_DOCUMENT(citizenshipDocumentId);
  const link = `${basePath}/knowledge`;
  const paddingRight = getPaddingRight(location.pathname, basePath);
  return (
    <CreateRelationshipContextProvider>
      {citizenshipDocument ? (
        <>
          <Routes>
            <Route
              path="/knowledge/*"
              element={(
                <StixCoreObjectKnowledgeBar
                  stixCoreObjectLink={link}
                  availableSections={[
                    'attack_patterns',
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
            <StixDomainObjectHeader
              entityType="Citizenship-Document"
              stixDomainObject={citizenshipDocument}
              noAliases
              EditComponent={(
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
              enableQuickSubscription={true}
              enableEnricher={true}
              enableEnrollPlaybook={true}
            />
            <StixDomainObjectMain
              entity={citizenshipDocument}
              basePath={basePath}
              pages={{
                overview: (
                  <CitizenshipDocument
                    citizenshipDocumentData={citizenshipDocument}
                  />
                ),
                knowledge: (
                  <div key={forceUpdate}>
                    <CitizenshipDocumentKnowledge
                      citizenshipDocumentData={citizenshipDocument}
                      relatedRelationshipTypes={['should-cover']}
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
                  />
                ),
                sightings: (
                  <EntityStixSightingRelationships
                    entityId={citizenshipDocument.id}
                    entityLink={link}
                    noPadding={true}
                    isTo={true}
                    stixCoreObjectTypes={[
                      'Threat-Actor',
                      'Intrusion-Set',
                      'Campaign',
                      'Malware',
                      'Tool',
                      'Vulnerability',
                      'Indicator',
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
