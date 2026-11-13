import { useMemo, Suspense } from 'react';
import { Route, Routes, useLocation, useParams } from 'react-router';
import { graphql, useSubscription, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import StixCoreRelationshipCreationFromEntityHeader from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntityHeader';
import CreateRelationshipContextProvider from '@components/common/stix_core_relationships/CreateRelationshipContextProvider';
import StixDomainObjectMain from '@components/common/stix_domain_objects/StixDomainObjectMain';
import { PATH_PROCEDURE, PATH_PROCEDURES } from '@components/common/routes/paths';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getPaddingRight } from '../../../../utils/utils';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import Procedure from './Procedure';
import ProcedureKnowledge, { PROCEDURE_KNOWLEDGE_SECTIONS } from './ProcedureKnowledge';
import ProcedureEdition from './ProcedureEdition';
import ProcedureDeletion from './ProcedureDeletion';
import { RootProcedureQuery } from './__generated__/RootProcedureQuery.graphql';
import { RootProcedureSubscription } from './__generated__/RootProcedureSubscription.graphql';

const subscription = graphql`
  subscription RootProcedureSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Procedure {
        ...Procedure_procedure
        ...ProcedureEditionOverview_procedure
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const procedureQuery = graphql`
  query RootProcedureQuery($id: String!) {
    procedure(id: $id) {
      id
      draftVersion {
        draft_id
        draft_operation
      }
      standard_id
      entity_type
      name
      x_opencti_graph_data
      currentUserAccessRight
      ...StixCoreRelationshipCreationFromEntityHeader_stixCoreObject
      ...StixCoreObjectKnowledgeBar_stixCoreObject
      ...Procedure_procedure
      ...ProcedureKnowledge_procedure
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
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

type RootProcedureProps = {
  procedureId: string;
  queryRef: PreloadedQuery<RootProcedureQuery>;
};

const RootProcedure = ({ procedureId, queryRef }: RootProcedureProps) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootProcedureSubscription>>(() => ({
    subscription,
    variables: { id: procedureId },
  }), [procedureId]);

  const location = useLocation();
  const { t_i18n } = useFormatter();
  useSubscription<RootProcedureSubscription>(subConfig);

  const {
    procedure,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery(procedureQuery, queryRef);

  const { forceUpdate } = useForceUpdate();

  const basePath = PATH_PROCEDURE(procedureId);
  const paddingRight = getPaddingRight(location.pathname, basePath);

  return (
    <CreateRelationshipContextProvider>
      {procedure ? (
        <>
          <Routes>
            <Route
              path="/knowledge/*"
              element={(
                <StixCoreObjectKnowledgeBar
                  stixCoreObjectLink={`${basePath}/knowledge`}
                  availableSections={PROCEDURE_KNOWLEDGE_SECTIONS}
                  data={procedure}
                />
              )}
            />
          </Routes>
          <div style={{ paddingRight }}>
            <Breadcrumbs elements={[
              { label: t_i18n('Techniques') },
              { label: t_i18n('Procedures'), link: PATH_PROCEDURES },
              { label: procedure.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="Procedure"
              stixDomainObject={procedure}
              EditComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <ProcedureEdition procedureId={procedure.id} />
                </Security>
              )}
              RelateComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <StixCoreRelationshipCreationFromEntityHeader data={procedure} />
                </Security>
              )}
              DeleteComponent={({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => (
                <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                  <ProcedureDeletion id={procedure.id} isOpen={isOpen} handleClose={onClose} />
                </Security>
              )}
              noAliases={true}
              redirectToContent={true}
              enableEnrollPlaybook={true}
            />
            <StixDomainObjectMain
              entity={procedure}
              basePath={basePath}
              pages={{
                overview: <Procedure procedureData={procedure} />,
                knowledge: (
                  <div key={forceUpdate}>
                    <ProcedureKnowledge procedureData={procedure} />
                  </div>
                ),
                content: <StixCoreObjectContentRoot stixCoreObject={procedure} />,
                analyses: <StixCoreObjectOrStixCoreRelationshipContainers stixDomainObjectOrStixCoreRelationship={procedure} />,
                files: (
                  <FileManager
                    id={procedureId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={procedure}
                  />
                ),
                history: <StixCoreObjectHistory stixCoreObjectId={procedureId} />,
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
  const { procedureId } = useParams() as { procedureId: string };
  const queryRef = useQueryLoading<RootProcedureQuery>(procedureQuery, { id: procedureId });

  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootProcedure procedureId={procedureId} queryRef={queryRef} />
        </Suspense>
      )}
    </>
  );
};

export default Root;
