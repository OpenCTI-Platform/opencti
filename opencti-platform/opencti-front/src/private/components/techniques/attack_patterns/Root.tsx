import { useMemo, Suspense } from 'react';
import { Route, Routes, useLocation, useParams } from 'react-router-dom';
import { graphql, useSubscription, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import { RootAttackPatternQuery } from '@components/techniques/attack_patterns/__generated__/RootAttackPatternQuery.graphql';
import { RootAttackPatternSubscription } from '@components/techniques/attack_patterns/__generated__/RootAttackPatternSubscription.graphql';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import StixCoreRelationshipCreationFromEntityHeader from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntityHeader';
import CreateRelationshipContextProvider from '@components/common/stix_core_relationships/CreateRelationshipContextProvider';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import AttackPattern from './AttackPattern';
import AttackPatternKnowledge from './AttackPatternKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixDomainObjectMain from '@components/common/stix_domain_objects/StixDomainObjectMain';
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
import AttackPatternEdition from './AttackPatternEdition';
import AttackPatternDeletion from './AttackPatternDeletion';

const subscription = graphql`
  subscription RootAttackPatternSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on AttackPattern {
        ...AttackPattern_attackPattern
        ...AttackPatternEditionContainer_attackPattern
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const attackPatternQuery = graphql`
  query RootAttackPatternQuery($id: String!) {
    attackPattern(id: $id) {
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
      ...AttackPattern_attackPattern
      ...AttackPatternKnowledge_attackPattern
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

type RootAttackPatternProps = {
  attackPatternId: string;
  queryRef: PreloadedQuery<RootAttackPatternQuery>;
};
const RootAttackPattern = ({ attackPatternId, queryRef }: RootAttackPatternProps) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootAttackPatternSubscription>>(() => ({
    subscription,
    variables: { id: attackPatternId },
  }), [attackPatternId]);

  const location = useLocation();
  const { t_i18n } = useFormatter();
  useSubscription<RootAttackPatternSubscription>(subConfig);

  const {
    attackPattern,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery(attackPatternQuery, queryRef);

  const { forceUpdate } = useForceUpdate();

  const paddingRight = getPaddingRight(location.pathname, attackPatternId, '/dashboard/techniques/attack_patterns');
  const link = `/dashboard/techniques/attack_patterns/${attackPatternId}/knowledge`;

  return (
    <CreateRelationshipContextProvider>
      {attackPattern ? (
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
                    'tools',
                    'vulnerabilities',
                    'malwares',
                    'indicators',
                    'observables',
                  ]}
                  data={attackPattern}
                />
              )}
            />
          </Routes>
          <div style={{ paddingRight }}>
            <Breadcrumbs elements={[
              { label: t_i18n('Techniques') },
              { label: t_i18n('Attack patterns'), link: '/dashboard/techniques/attack_patterns' },
              { label: attackPattern.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="Attack-Pattern"
              stixDomainObject={attackPattern}
              EditComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <AttackPatternEdition attackPatternId={attackPattern.id} />
                </Security>
              )}
              RelateComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <StixCoreRelationshipCreationFromEntityHeader
                    data={attackPattern}
                  />
                </Security>
              )}
              DeleteComponent={({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => (
                <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                  <AttackPatternDeletion id={attackPattern.id} isOpen={isOpen} handleClose={onClose} />
                </Security>
              )}
              redirectToContent={true}
              enableEnrollPlaybook={true}
            />
            <StixDomainObjectMain
              basePath="/dashboard/techniques/attack_patterns"
              entity={attackPattern}
              pages={{
                overview:
                  <AttackPattern attackPatternData={attackPattern} />,
                knowledge: (
                  <div key={forceUpdate}>
                    <AttackPatternKnowledge attackPatternData={attackPattern} />
                  </div>
                ),
                content: (
                  <StixCoreObjectContentRoot
                    stixCoreObject={attackPattern}
                  />
                ),
                analyses:
                  <StixCoreObjectOrStixCoreRelationshipContainers stixDomainObjectOrStixCoreRelationship={attackPattern} />,
                files: (
                  <FileManager
                    id={attackPatternId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={attackPattern}
                  />
                ),
                history:
                  <StixCoreObjectHistory stixCoreObjectId={attackPatternId} />,
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
  const { attackPatternId } = useParams() as { attackPatternId: string };
  const queryRef = useQueryLoading<RootAttackPatternQuery>(attackPatternQuery, {
    id: attackPatternId,
  });

  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootAttackPattern attackPatternId={attackPatternId} queryRef={queryRef} />
        </Suspense>
      )}
    </>
  );
};

export default Root;
