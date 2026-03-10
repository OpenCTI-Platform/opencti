import { useMemo, Suspense } from 'react';
import { Route, Routes, Navigate, useLocation, useParams } from 'react-router-dom';
import { graphql, useSubscription, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import StixDomainObjectTabsBox from '@components/common/stix_domain_objects/StixDomainObjectTabsBox';
import StixCoreRelationshipCreationFromEntityHeader from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntityHeader';
import CreateRelationshipContextProvider from '@components/common/stix_core_relationships/CreateRelationshipContextProvider';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import Vulnerability from './Vulnerability';
import VulnerabilityKnowledge from './VulnerabilityKnowledge';
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
import { RootVulnerabilityQuery } from './__generated__/RootVulnerabilityQuery.graphql';
import { RootVulnerabilitySubscription } from './__generated__/RootVulnerabilitySubscription.graphql';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import VulnerabilityEdition from './VulnerabilityEdition';
import VulnerabilityDeletion from './VulnerabilityDeletion';
import { useEntityLabelResolver } from '../../../../utils/hooks/useEntityLabel';

const subscription = graphql`
  subscription RootVulnerabilitySubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Vulnerability {
        ...Vulnerability_vulnerability
        ...VulnerabilityEditionContainer_vulnerability
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const vulnerabilityQuery = graphql`
  query RootVulnerabilityQuery($id: String!) {
    vulnerability(id: $id) {
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
      ...Vulnerability_vulnerability
      ...VulnerabilityKnowledge_vulnerability
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

type RootVulnerabilityProps = {
  vulnerabilityId: string;
  queryRef: PreloadedQuery<RootVulnerabilityQuery>;
};

const RootVulnerability = ({ queryRef, vulnerabilityId }: RootVulnerabilityProps) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootVulnerabilitySubscription>>(() => ({
    subscription,
    variables: { id: vulnerabilityId },
  }), [vulnerabilityId]);

  const location = useLocation();
  const { t_i18n } = useFormatter();
  const entityLabel = useEntityLabelResolver();
  useSubscription<RootVulnerabilitySubscription>(subConfig);

  const {
    vulnerability,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootVulnerabilityQuery>(vulnerabilityQuery, queryRef);

  const { forceUpdate } = useForceUpdate();

  const paddingRight = getPaddingRight(location.pathname, vulnerabilityId, '/dashboard/arsenal/vulnerabilities');
  const link = `/dashboard/arsenal/vulnerabilities/${vulnerabilityId}/knowledge`;
  return (
    <CreateRelationshipContextProvider>
      {vulnerability ? (
        <>
          <Routes>
            <Route
              path="/knowledge/*"
              element={(
                <StixCoreObjectKnowledgeBar
                  stixCoreObjectLink={link}
                  availableSections={[
                    'threats',
                    'threat_actors',
                    'intrusion_sets',
                    'campaigns',
                    'incidents',
                    'malwares',
                    'tools',
                    'attack_patterns',
                    'indicators',
                    'observables',
                    'sightings',
                    'infrastructures',
                  ]}
                  data={vulnerability}
                />
              )}
            />
          </Routes>
          <div style={{ paddingRight }}>
            <Breadcrumbs elements={[
              { label: t_i18n('Arsenal') },
              { label: entityLabel('Vulnerability', t_i18n('Vulnerabilities')), link: '/dashboard/arsenal/vulnerabilities' },
              { label: vulnerability.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="Vulnerability"
              stixDomainObject={vulnerability}
              EditComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <VulnerabilityEdition vulnerabilityId={vulnerabilityId} />
                </Security>
              )}
              RelateComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <StixCoreRelationshipCreationFromEntityHeader
                    data={vulnerability}
                  />
                </Security>
              )}
              DeleteComponent={({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => (
                <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                  <VulnerabilityDeletion id={vulnerability.id} isOpen={isOpen} handleClose={onClose} />
                </Security>
              )}
              enableEnricher={true}
              enableQuickSubscription={true}
              isOpenctiAlias={true}
              redirectToContent={true}
              enableEnrollPlaybook={true}
            />
            <StixDomainObjectTabsBox
              basePath="/dashboard/arsenal/vulnerabilities"
              entity={vulnerability}
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
                element={(
                  <Vulnerability
                    vulnerabilityData={vulnerability}
                  />
                )}
              />
              <Route
                path="/knowledge"
                element={(
                  <Navigate
                    replace={true}
                    to={`/dashboard/arsenal/vulnerabilities/${vulnerabilityId}/knowledge/overview`}
                  />
                )}
              />
              <Route
                path="/knowledge/*"
                element={(
                  <div key={forceUpdate}>
                    <VulnerabilityKnowledge vulnerabilityData={vulnerability} />
                  </div>
                )}
              />
              <Route
                path="/content/*"
                element={(
                  <StixCoreObjectContentRoot
                    stixCoreObject={vulnerability}
                  />
                )}
              />
              <Route
                path="/analyses"
                element={(
                  <StixCoreObjectOrStixCoreRelationshipContainers
                    stixDomainObjectOrStixCoreRelationship={vulnerability}
                  />
                )}
              />
              <Route
                path="/files"
                element={(
                  <FileManager
                    id={vulnerabilityId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={vulnerability}
                  />
                )}
              />
              <Route
                path="/history"
                element={(
                  <StixCoreObjectHistory
                    stixCoreObjectId={vulnerabilityId}
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
  const { vulnerabilityId } = useParams() as { vulnerabilityId: string };
  const queryRef = useQueryLoading<RootVulnerabilityQuery>(vulnerabilityQuery, {
    id: vulnerabilityId,
  });

  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootVulnerability queryRef={queryRef} vulnerabilityId={vulnerabilityId} />
        </Suspense>
      )}
    </>
  );
};

export default Root;
