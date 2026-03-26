import { useMemo, Suspense } from 'react';
import { Route, Routes, Navigate, useLocation, useParams } from 'react-router-dom';
import { graphql, useSubscription, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import { RootNarrativeQuery } from '@components/techniques/narratives/__generated__/RootNarrativeQuery.graphql';
import { RootNarrativeSubscription } from '@components/techniques/narratives/__generated__/RootNarrativeSubscription.graphql';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import CreateRelationshipContextProvider from '@components/common/stix_core_relationships/CreateRelationshipContextProvider';
import StixCoreRelationshipCreationFromEntityHeader from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntityHeader';
import StixDomainObjectTabsBox from '@components/common/stix_domain_objects/StixDomainObjectTabsBox';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import Narrative from './Narrative';
import NarrativeKnowledge from './NarrativeKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getPaddingRight } from '../../../../utils/utils';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import NarrativeEdition from './NarrativeEdition';
import NarrativeDeletion from './NarrativeDeletion';
import useEntityTranslation from '../../../../utils/hooks/useEntityTranslation';

const subscription = graphql`
  subscription RootNarrativeSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Narrative {
        ...Narrative_narrative
        ...NarrativeEditionContainer_narrative
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const narrativeQuery = graphql`
  query RootNarrativeQuery($id: String!) {
    narrative(id: $id) {
      id
      draftVersion {
        draft_id
        draft_operation
      }
      standard_id
      entity_type
      name
      aliases
      x_opencti_graph_data
      currentUserAccessRight
      ...StixCoreRelationshipCreationFromEntityHeader_stixCoreObject
      ...StixCoreObjectKnowledgeBar_stixCoreObject
      ...Narrative_narrative
      ...NarrativeKnowledge_narrative
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

type RootNarrativeProps = {
  narrativeId: string;
  queryRef: PreloadedQuery<RootNarrativeQuery>;
};
const RootNarrative = ({ narrativeId, queryRef }: RootNarrativeProps) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootNarrativeSubscription>>(() => ({
    subscription,
    variables: { id: narrativeId },
  }), [narrativeId]);

  const location = useLocation();
  const { t_i18n } = useFormatter();
  const { translateEntityType } = useEntityTranslation();
  useSubscription<RootNarrativeSubscription>(subConfig);

  const {
    narrative,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootNarrativeQuery>(narrativeQuery, queryRef);

  const { forceUpdate } = useForceUpdate();

  const paddingRight = getPaddingRight(location.pathname, narrativeId, '/dashboard/techniques/narratives');
  const link = `/dashboard/techniques/narratives/${narrativeId}/knowledge`;
  return (
    <CreateRelationshipContextProvider>
      {narrative ? (
        <>
          <Routes>
            <Route
              path="/knowledge/*"
              element={(
                <StixCoreObjectKnowledgeBar
                  stixCoreObjectLink={link}
                  availableSections={[
                    'threat_actors',
                    'intrusion_sets',
                    'campaigns',
                    'incidents',
                    'channels',
                    'observables',
                    'sightings',
                  ]}
                  data={narrative}
                />
              )}
            />
          </Routes>
          <div style={{ paddingRight }}>
            <Breadcrumbs elements={[
              { label: t_i18n('Techniques') },
              { label: translateEntityType('Narrative', { plural: true }), link: '/dashboard/techniques/narratives' },
              { label: narrative.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="Narrative"
              stixDomainObject={narrative}
              enableEnrollPlaybook={true}
              EditComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <NarrativeEdition narrativeId={narrative.id} />
                </Security>
              )}
              RelateComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <StixCoreRelationshipCreationFromEntityHeader
                    data={narrative}
                  />
                </Security>
              )}
              DeleteComponent={({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => (
                <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                  <NarrativeDeletion id={narrative.id} isOpen={isOpen} handleClose={onClose} />
                </Security>
              )}
            />
            <StixDomainObjectTabsBox
              basePath="/dashboard/techniques/narratives"
              entity={narrative}
              tabs={[
                'overview',
                'knowledge-overview',
                'content',
                'analyses',
                'files',
                'history',
              ]}
            />
            <Routes>
              <Route
                path="/"
                element={
                  <Narrative narrativeData={narrative} />
                }
              />
              <Route
                path="/knowledge"
                element={
                  <Navigate to={`/dashboard/techniques/narratives/${narrativeId}/knowledge/overview`} replace={true} />
                }
              />
              <Route
                path="/knowledge/*"
                element={(
                  <div key={forceUpdate}>
                    <NarrativeKnowledge narrativeData={narrative} />
                  </div>
                )}
              />
              <Route
                path="/content/*"
                element={(
                  <StixCoreObjectContentRoot
                    stixCoreObject={narrative}
                  />
                )}
              />
              <Route
                path="/analyses"
                element={
                  <StixCoreObjectOrStixCoreRelationshipContainers stixDomainObjectOrStixCoreRelationship={narrative} />
                }
              />
              <Route
                path="/files"
                element={(
                  <FileManager
                    id={narrativeId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={narrative}
                  />
                )}
              />
              <Route
                path="/history"
                element={
                  <StixCoreObjectHistory stixCoreObjectId={narrativeId} />
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
  const { narrativeId } = useParams() as { narrativeId: string };
  const queryRef = useQueryLoading<RootNarrativeQuery>(narrativeQuery, {
    id: narrativeId,
  });

  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootNarrative narrativeId={narrativeId} queryRef={queryRef} />
        </Suspense>
      )}
    </>
  );
};

export default Root;
