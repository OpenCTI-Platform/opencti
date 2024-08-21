import React, { useMemo, Suspense } from 'react';
import { Route, Routes, Link, Navigate, useLocation, useParams } from 'react-router-dom';
import { graphql, useSubscription, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import Vulnerability from './Vulnerability';
import VulnerabilityKnowledge from './VulnerabilityKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import VulnerabilityPopover from './VulnerabilityPopover';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';
import { RootVulnerabilityQuery } from './__generated__/RootVulnerabilityQuery.graphql';
import { RootVulnerabilitySubscription } from './__generated__/RootVulnerabilitySubscription.graphql';

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
      standard_id
      entity_type
      name
      x_opencti_aliases
      x_opencti_graph_data
      stixCoreObjectsDistribution(field: "entity_type", operation: count) {
        label
        value
      }
      ...Vulnerability_vulnerability
      ...VulnerabilityKnowledge_vulnerability
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
  useSubscription<RootVulnerabilitySubscription>(subConfig);

  const {
    vulnerability,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootVulnerabilityQuery>(vulnerabilityQuery, queryRef);

  const paddingRight = getPaddingRight(location.pathname, vulnerabilityId, '/dashboard/arsenal/vulnerabilities');
  const link = `/dashboard/arsenal/vulnerabilities/${vulnerabilityId}/knowledge`;
  return (
    <>
      {vulnerability ? (
        <>
          <Routes>
            <Route
              path="/knowledge/*"
              element={
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
                  stixCoreObjectsDistribution={vulnerability.stixCoreObjectsDistribution}
                />
                                  }
            />
          </Routes>
          <div style={{ paddingRight }}>
            <Breadcrumbs variant="object" elements={[
              { label: t_i18n('Arsenal') },
              { label: t_i18n('Vulnerabilities'), link: '/dashboard/arsenal/vulnerabilities' },
              { label: vulnerability.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="Vulnerability"
              stixDomainObject={vulnerability}
              PopoverComponent={<VulnerabilityPopover />}
              enableQuickSubscription={true}
              isOpenctiAlias={true}
            />
            <Box
              sx={{
                borderBottom: 1,
                borderColor: 'divider',
                marginBottom: 4,
              }}
            >
              <Tabs
                value={getCurrentTab(location.pathname, vulnerability.id, '/dashboard/arsenal/vulnerabilities')}
              >
                <Tab
                  component={Link}
                  to={`/dashboard/arsenal/vulnerabilities/${vulnerability.id}`}
                  value={`/dashboard/arsenal/vulnerabilities/${vulnerability.id}`}
                  label={t_i18n('Overview')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/arsenal/vulnerabilities/${vulnerability.id}/knowledge/overview`}
                  value={`/dashboard/arsenal/vulnerabilities/${vulnerability.id}/knowledge`}
                  label={t_i18n('Knowledge')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/arsenal/vulnerabilities/${vulnerability.id}/content`}
                  value={`/dashboard/arsenal/vulnerabilities/${vulnerability.id}/content`}
                  label={t_i18n('Content')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/arsenal/vulnerabilities/${vulnerability.id}/analyses`}
                  value={`/dashboard/arsenal/vulnerabilities/${vulnerability.id}/analyses`}
                  label={t_i18n('Analyses')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/arsenal/vulnerabilities/${vulnerability.id}/files`}
                  value={`/dashboard/arsenal/vulnerabilities/${vulnerability.id}/files`}
                  label={t_i18n('Data')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/arsenal/vulnerabilities/${vulnerability.id}/history`}
                  value={`/dashboard/arsenal/vulnerabilities/${vulnerability.id}/history`}
                  label={t_i18n('History')}
                />
              </Tabs>
            </Box>
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
                element={<VulnerabilityKnowledge vulnerability={vulnerability}/>}
              />
              <Route
                path="/content/*"
                element={
                  <StixCoreObjectContentRoot
                    stixCoreObject={vulnerability}
                  />
                }
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
    </>
  );
};

const Root = () => {
  const { vulnerabilityId } = useParams() as { vulnerabilityId: string; };
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
