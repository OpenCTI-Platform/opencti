import React, { useMemo } from 'react';
import { Navigate, Route, Routes, useLocation, useParams } from 'react-router-dom';
import { graphql, PreloadedQuery, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import StixCoreObjectContentRoot from '@components/common/stix_core_objects/StixCoreObjectContentRoot';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import AIInsights from '@components/common/ai/AIInsights';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import { RootThreatActorIndividualQuery } from './__generated__/RootThreatActorIndividualQuery.graphql';
import { RootThreatActorIndividualSubscription } from './__generated__/RootThreatActorIndividualSubscription.graphql';
import ThreatActorIndividual from './ThreatActorIndividual';
import StixDomainObjectTabsBox from '@components/common/stix_domain_objects/StixDomainObjectTabsBox';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import ThreatActorIndividualKnowledge from './ThreatActorIndividualKnowledge';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getPaddingRight } from '../../../../utils/utils';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import ThreatActorIndividualEdition from './ThreatActorIndividualEdition';
import ThreatActorIndividualDeletion from './ThreatActorIndividualDeletion';
import StixCoreRelationshipCreationFromEntityHeader from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntityHeader';
import CreateRelationshipContextProvider from '../../common/stix_core_relationships/CreateRelationshipContextProvider';
import { useEntityLabelResolver } from '../../../../utils/hooks/useEntityLabel';

const subscription = graphql`
  subscription RootThreatActorIndividualSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on ThreatActorIndividual {
        ...ThreatActorIndividual_ThreatActorIndividual
        ...ThreatActorIndividualEditionOverview_ThreatActorIndividual
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...PictureManagementViewer_entity
    }
  }
`;

const ThreatActorIndividualQuery = graphql`
  query RootThreatActorIndividualQuery($id: String!, $relatedRelationshipTypes: [String!]) {
    threatActorIndividual(id: $id) {
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
      ...StixCoreObjectKnowledgeBar_stixCoreObject @arguments(relatedRelationshipTypes: $relatedRelationshipTypes)
      ...ThreatActorIndividual_ThreatActorIndividual
      ...ThreatActorIndividualKnowledge_ThreatActorIndividual
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...PictureManagementViewer_entity
      ...StixCoreObjectContent_stixCoreObject
      ...StixCoreObjectSharingListFragment
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
    connectorsForImport {
      ...FileManager_connectorsImport
    }
  }
`;

const THREAT_ACTOR_INDIVIDUAL_RELATED_RELATIONSHIP_TYPES = ['related-to', 'part-of', 'impersonates', 'known-as'];

type RootThreatActorIndividualProps = {
  threatActorIndividualId: string;
  queryRef: PreloadedQuery<RootThreatActorIndividualQuery>;
};

const RootThreatActorIndividualComponent = ({
  queryRef,
  threatActorIndividualId,
}: RootThreatActorIndividualProps) => {
  const subConfig = useMemo<
    GraphQLSubscriptionConfig<RootThreatActorIndividualSubscription>
  >(
    () => ({
      subscription,
      variables: { id: threatActorIndividualId },
    }),
    [threatActorIndividualId],
  );
  const location = useLocation();
  const { t_i18n } = useFormatter();
  const entityLabel = useEntityLabelResolver();
  useSubscription<RootThreatActorIndividualSubscription>(subConfig);
  const {
    threatActorIndividual,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootThreatActorIndividualQuery>(
    ThreatActorIndividualQuery,
    queryRef,
  );
  const { forceUpdate } = useForceUpdate();
  const isOverview = location.pathname === `/dashboard/threats/threat_actors_individual/${threatActorIndividualId}`;
  const paddingRight = getPaddingRight(location.pathname, threatActorIndividualId, '/dashboard/threats/threat_actors_individual');
  const link = `/dashboard/threats/threat_actors_individual/${threatActorIndividualId}/knowledge`;
  return (
    <CreateRelationshipContextProvider>
      {threatActorIndividual ? (
        <>
          <Routes>
            <Route
              path="/knowledge/*"
              element={(
                <StixCoreObjectKnowledgeBar
                  stixCoreObjectLink={link}
                  availableSections={[
                    'victimology',
                    'threat_actors',
                    'intrusion_sets',
                    'campaigns',
                    'incidents',
                    'organizations',
                    'malwares',
                    'attack_patterns',
                    'channels',
                    'narratives',
                    'tools',
                    'vulnerabilities',
                    'indicators',
                    'observables',
                    'infrastructures',
                    'sightings',
                    'countries',
                  ]}
                  data={threatActorIndividual}
                />
              )}
            />
          </Routes>
          <div style={{ paddingRight }}>
            <Breadcrumbs elements={[
              { label: t_i18n('Threats') },
              { label: entityLabel('Threat-Actor-Individual', t_i18n('Threat actors (individual)')), link: '/dashboard/threats/threat_actors_individual' },
              { label: threatActorIndividual.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="Threat-Actor-Individual"
              stixDomainObject={threatActorIndividual}
              EditComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <ThreatActorIndividualEdition
                    threatActorIndividualId={threatActorIndividual.id}
                  />
                </Security>
              )}
              RelateComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <StixCoreRelationshipCreationFromEntityHeader
                    data={threatActorIndividual}
                  />
                </Security>
              )}
              DeleteComponent={({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => (
                <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                  <ThreatActorIndividualDeletion id={threatActorIndividual.id} isOpen={isOpen} handleClose={onClose} />
                </Security>
              )}
              enableEnricher={true}
              enableQuickSubscription={true}
              redirectToContent={true}
              enableEnrollPlaybook={true}
            />
            <StixDomainObjectTabsBox
              basePath="/dashboard/threats/threat_actors_individual"
              entity={threatActorIndividual}
              tabs={[
                'overview',
                'knowledge-overview',
                'content',
                'analyses',
                'files',
                'history',
              ]}
              extraActions={isOverview && <AIInsights id={threatActorIndividual.id} />}
            />
            <Routes>
              <Route
                path="/"
                element={
                  <ThreatActorIndividual threatActorIndividualData={threatActorIndividual} />
                }
              />
              <Route
                path="/knowledge"
                element={
                  <Navigate to={`/dashboard/threats/threat_actors_individual/${threatActorIndividual.id}/knowledge/overview`} replace={true} />
                }
              />
              <Route
                path="/knowledge/*"
                element={(
                  <div key={forceUpdate}>
                    <ThreatActorIndividualKnowledge
                      threatActorIndividualData={threatActorIndividual}
                      relatedRelationshipTypes={THREAT_ACTOR_INDIVIDUAL_RELATED_RELATIONSHIP_TYPES}
                    />
                  </div>
                )}
              />
              <Route
                path="/content/*"
                element={(
                  <StixCoreObjectContentRoot
                    stixCoreObject={threatActorIndividual}
                  />
                )}
              />
              <Route
                path="/analyses"
                element={
                  <StixCoreObjectOrStixCoreRelationshipContainers stixDomainObjectOrStixCoreRelationship={threatActorIndividual} />
                }
              />
              <Route
                path="/files"
                element={(
                  <FileManager
                    id={threatActorIndividualId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={threatActorIndividual}
                  />
                )}
              />
              <Route
                path="/history"
                element={
                  <StixCoreObjectHistory stixCoreObjectId={threatActorIndividualId} />
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
  const { threatActorIndividualId } = useParams() as {
    threatActorIndividualId: string;
  };
  const queryRef = useQueryLoading<RootThreatActorIndividualQuery>(
    ThreatActorIndividualQuery,
    {
      id: threatActorIndividualId,
      relatedRelationshipTypes: THREAT_ACTOR_INDIVIDUAL_RELATED_RELATIONSHIP_TYPES,
    },
  );
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootThreatActorIndividualComponent
            queryRef={queryRef}
            threatActorIndividualId={threatActorIndividualId}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default Root;
