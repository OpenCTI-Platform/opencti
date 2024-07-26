import React, { useMemo, Suspense } from 'react';
import { Route, Routes, Link, Navigate, useLocation, useParams } from 'react-router-dom';
import { graphql, useSubscription, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import { RootAttackPatternQuery } from '@components/techniques/attack_patterns/__generated__/RootAttackPatternQuery.graphql';
import { RootAttackPatternSubscription } from '@components/techniques/attack_patterns/__generated__/RootAttackPatternSubscription.graphql';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import AttackPattern from './AttackPattern';
import AttackPatternKnowledge from './AttackPatternKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import AttackPatternPopover from './AttackPatternPopover';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import AttackPatternEdition from './AttackPatternEdition';
import useHelper from '../../../../utils/hooks/useHelper';
import CreateRelationshipContextProvider from '../../common/menus/CreateRelationshipContextProvider';
import CreateRelationshipButtonComponent from '../../common/menus/CreateRelationshipButtonComponent';

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
      standard_id
      entity_type
      name
      aliases
      x_opencti_graph_data
      stixCoreObjectsDistribution(field: "entity_type", operation: count) {
        label
        value
      }
      ...AttackPattern_attackPattern
      ...AttackPatternKnowledge_attackPattern
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
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
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
              element={
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
                  stixCoreObjectsDistribution={attackPattern.stixCoreObjectsDistribution}
                />
              }
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
              PopoverComponent={<AttackPatternPopover id={attackPattern.id}/>}
              EditComponent={isFABReplaced && (
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <AttackPatternEdition attackPatternId={attackPattern.id} />
                </Security>
              )}
              RelateComponent={CreateRelationshipButtonComponent}
            />
            <Box
              sx={{
                borderBottom: 1,
                borderColor: 'divider',
                marginBottom: 3,
              }}
            >
              <Tabs
                value={getCurrentTab(location.pathname, attackPattern.id, '/dashboard/techniques/attack_patterns')}
              >
                <Tab
                  component={Link}
                  to={`/dashboard/techniques/attack_patterns/${attackPattern.id}`}
                  value={`/dashboard/techniques/attack_patterns/${attackPattern.id}`}
                  label={t_i18n('Overview')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/techniques/attack_patterns/${attackPattern.id}/knowledge/overview`}
                  value={`/dashboard/techniques/attack_patterns/${attackPattern.id}/knowledge`}
                  label={t_i18n('Knowledge')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/techniques/attack_patterns/${attackPattern.id}/content`}
                  value={`/dashboard/techniques/attack_patterns/${attackPattern.id}/content`}
                  label={t_i18n('Content')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/techniques/attack_patterns/${attackPattern.id}/analyses`}
                  value={`/dashboard/techniques/attack_patterns/${attackPattern.id}/analyses`}
                  label={t_i18n('Analyses')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/techniques/attack_patterns/${attackPattern.id}/files`}
                  value={`/dashboard/techniques/attack_patterns/${attackPattern.id}/files`}
                  label={t_i18n('Data')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/techniques/attack_patterns/${attackPattern.id}/history`}
                  value={`/dashboard/techniques/attack_patterns/${attackPattern.id}/history`}
                  label={t_i18n('History')}
                />
              </Tabs>
            </Box>
            <Routes>
              <Route
                path="/"
                element={
                  <AttackPattern attackPatternData={attackPattern} />
                }
              />
              <Route
                path="/knowledge"
                element={
                  <Navigate to={`/dashboard/techniques/attack_patterns/${attackPatternId}/knowledge/overview`} replace={true} />
                }
              />
              <Route
                path="/knowledge/*"
                element={
                  <div key={forceUpdate}>
                    <AttackPatternKnowledge attackPattern={attackPattern} />
                  </div>
                }
              />
              <Route
                path="/content/*"
                element={
                  <StixCoreObjectContentRoot
                    stixCoreObject={attackPattern}
                  />
                }
              />
              <Route
                path="/analyses"
                element={
                  <StixCoreObjectOrStixCoreRelationshipContainers stixDomainObjectOrStixCoreRelationship={attackPattern} />
                }
              />
              <Route
                path="/files"
                element={
                  <FileManager
                    id={attackPatternId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={attackPattern}
                  />
                }
              />
              <Route
                path="/history"
                element={
                  <StixCoreObjectHistory stixCoreObjectId={attackPatternId} />
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
  const { attackPatternId } = useParams() as { attackPatternId: string; };
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
