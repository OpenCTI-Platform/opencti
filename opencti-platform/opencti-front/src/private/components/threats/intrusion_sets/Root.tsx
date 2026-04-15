import { Suspense, useMemo } from 'react';
import { Route, Routes, useLocation, useParams } from 'react-router-dom';
import { graphql, PreloadedQuery, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import AIInsights from '@components/common/ai/AIInsights';
import StixCoreObjectSecurityCoverage from '@components/common/stix_core_objects/StixCoreObjectSecurityCoverage';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import IntrusionSet from './IntrusionSet';
import IntrusionSetKnowledge from './IntrusionSetKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixDomainObjectMain from '@components/common/stix_domain_objects/StixDomainObjectMain';
import FileManager from '../../common/files/FileManager';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getPaddingRight } from '../../../../utils/utils';
import { RootIntrusionSetQuery } from './__generated__/RootIntrusionSetQuery.graphql';
import { RootIntrusionSetSubscription } from './__generated__/RootIntrusionSetSubscription.graphql';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import IntrusionSetEdition from './IntrusionSetEdition';
import IntrusionSetDeletion from './IntrusionSetDeletion';
import StixCoreRelationshipCreationFromEntityHeader from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntityHeader';
import CreateRelationshipContextProvider from '../../common/stix_core_relationships/CreateRelationshipContextProvider';
import { PATH_INTRUSION_SET, PATH_INTRUSION_SETS } from '@components/common/routes/paths';

const subscription = graphql`
  subscription RootIntrusionSetSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on IntrusionSet {
        ...IntrusionSet_intrusionSet
        ...IntrusionSetEditionContainer_intrusionSet
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...PictureManagementViewer_entity
    }
  }
`;

const intrusionSetQuery = graphql`
  query RootIntrusionSetQuery($id: String!) {
    intrusionSet(id: $id) {
      id
      draftVersion {
        draft_id
        draft_operation
      }
      standard_id
      entity_type
      name
      aliases
      objectMarking {
        id
      }
      x_opencti_graph_data
      currentUserAccessRight
      securityCoverage {
        id
        coverage_information {
          coverage_name
          coverage_score
        }
      }
      ...StixCoreRelationshipCreationFromEntityHeader_stixCoreObject
      ...StixCoreObjectKnowledgeBar_stixCoreObject
      ...IntrusionSet_intrusionSet
      ...IntrusionSetKnowledge_intrusionSet
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

type RootIntrusionSetProps = {
  intrusionSetId: string;
  queryRef: PreloadedQuery<RootIntrusionSetQuery>;
};

const RootIntrusionSet = ({ intrusionSetId, queryRef }: RootIntrusionSetProps) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootIntrusionSetSubscription>>(() => ({
    subscription,
    variables: { id: intrusionSetId },
  }), [intrusionSetId]);
  const location = useLocation();
  const { t_i18n } = useFormatter();
  useSubscription<RootIntrusionSetSubscription>(subConfig);
  const {
    intrusionSet,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootIntrusionSetQuery>(intrusionSetQuery, queryRef);
  const { forceUpdate } = useForceUpdate();
  const basePath = PATH_INTRUSION_SET(intrusionSetId);
  const isOverview = location.pathname === basePath;
  const paddingRight = getPaddingRight(location.pathname, basePath);
  const link = `${basePath}/knowledge`;
  return (
    <CreateRelationshipContextProvider>
      {intrusionSet ? (
        <>
          <Routes>
            <Route
              path="/knowledge/*"
              element={(
                <StixCoreObjectKnowledgeBar
                  stixCoreObjectLink={link}
                  availableSections={[
                    'victimology',
                    'attribution',
                    'campaigns',
                    'incidents',
                    'malwares',
                    'attack_patterns',
                    'tools',
                    'channels',
                    'narratives',
                    'vulnerabilities',
                    'indicators',
                    'observables',
                    'infrastructures',
                    'sightings',
                    'intrusion_sets',
                  ]}
                  data={intrusionSet}
                  attribution={['Threat-Actor-Individual', 'Threat-Actor-Group']}
                />
              )}
            />
          </Routes>
          <div style={{ paddingRight }} data-testid="intrusionSet-details-page">
            <Breadcrumbs elements={[
              { label: t_i18n('Threats') },
              { label: t_i18n('Intrusion sets'), link: PATH_INTRUSION_SETS },
              { label: intrusionSet.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="Intrusion-Set"
              stixDomainObject={intrusionSet}
              EditComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <IntrusionSetEdition intrusionSetId={intrusionSet.id} />
                </Security>
              )}
              RelateComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <StixCoreRelationshipCreationFromEntityHeader
                    data={intrusionSet}
                  />
                </Security>
              )}
              DeleteComponent={({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => (
                <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                  <IntrusionSetDeletion id={intrusionSet.id} isOpen={isOpen} handleClose={onClose} />
                </Security>
              )}
              enableEnricher={true}
              enableQuickSubscription={true}
              redirectToContent={true}
              enableEnrollPlaybook={true}
            />
            <StixDomainObjectMain
              basePath={basePath}
              pages={{
                overview:
                  <IntrusionSet intrusionSetData={intrusionSet} />,
                knowledge: (
                  <div key={forceUpdate}>
                    <IntrusionSetKnowledge intrusionSetData={intrusionSet} />
                  </div>
                ),
                content: (
                  <StixCoreObjectContentRoot
                    stixCoreObject={intrusionSet}
                  />
                ),
                analyses:
                  <StixCoreObjectOrStixCoreRelationshipContainers stixDomainObjectOrStixCoreRelationship={intrusionSet} />,
                files: (
                  <FileManager
                    id={intrusionSetId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={intrusionSet}
                  />
                ),
                history:
                  <StixCoreObjectHistory stixCoreObjectId={intrusionSetId} />,
              }}
              extraActions={isOverview && (
                <>
                  <AIInsights id={intrusionSet.id} />
                  <StixCoreObjectSecurityCoverage id={intrusionSet.id} coverage={intrusionSet.securityCoverage} />
                </>
              )}
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
  const { intrusionSetId } = useParams() as { intrusionSetId: string };
  const queryRef = useQueryLoading<RootIntrusionSetQuery>(intrusionSetQuery, {
    id: intrusionSetId,
  });

  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootIntrusionSet queryRef={queryRef} intrusionSetId={intrusionSetId} />
        </Suspense>
      )}
    </>
  );
};

export default Root;
