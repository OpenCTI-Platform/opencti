import React, { useMemo, Suspense } from 'react';
import { Route, Routes, Link, Navigate, useLocation, useParams } from 'react-router-dom';
import { graphql, useSubscription, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { RootNarrativeQuery } from '@components/techniques/narratives/__generated__/RootNarrativeQuery.graphql';
import { RootNarrativeSubscription } from '@components/techniques/narratives/__generated__/RootNarrativeSubscription.graphql';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import Narrative from './Narrative';
import NarrativeKnowledge from './NarrativeKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import NarrativePopover from './NarrativePopover';
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
import NarrativeEdition from './NarrativeEdition';
import useHelper from '../../../../utils/hooks/useHelper';
import CreateRelationshipContextProvider from '../../common/menus/CreateRelationshipContextProvider';
import CreateRelationshipButtonComponent from '../../common/menus/CreateRelationshipButtonComponent';

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
      standard_id
      entity_type
      name
      aliases
      x_opencti_graph_data
      stixCoreObjectsDistribution(field: "entity_type", operation: count) {
        label
        value
      }
      ...Narrative_narrative
      ...NarrativeKnowledge_narrative
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
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const { t_i18n } = useFormatter();
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
              element={
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
                  stixCoreObjectsDistribution={narrative.stixCoreObjectsDistribution}
                />
              }
            />
          </Routes>
          <div style={{ paddingRight }} >
            <Breadcrumbs elements={[
              { label: t_i18n('Techniques') },
              { label: t_i18n('Narratives'), link: '/dashboard/techniques/narratives' },
              { label: narrative.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="Narrative"
              stixDomainObject={narrative}
              PopoverComponent={<NarrativePopover id={narrative.id}/>}
              EditComponent={isFABReplaced && (
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <NarrativeEdition narrativeId={narrative.id} />
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
                value={getCurrentTab(location.pathname, narrative.id, '/dashboard/techniques/narratives')}
              >
                <Tab
                  component={Link}
                  to={`/dashboard/techniques/narratives/${narrative.id}`}
                  value={`/dashboard/techniques/narratives/${narrative.id}`}
                  label={t_i18n('Overview')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/techniques/narratives/${narrative.id}/knowledge/overview`}
                  value={`/dashboard/techniques/narratives/${narrative.id}/knowledge`}
                  label={t_i18n('Knowledge')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/techniques/narratives/${narrative.id}/content`}
                  value={`/dashboard/techniques/narratives/${narrative.id}/content`}
                  label={t_i18n('Content')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/techniques/narratives/${narrative.id}/analyses`}
                  value={`/dashboard/techniques/narratives/${narrative.id}/analyses`}
                  label={t_i18n('Analyses')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/techniques/narratives/${narrative.id}/files`}
                  value={`/dashboard/techniques/narratives/${narrative.id}/files`}
                  label={t_i18n('Data')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/techniques/narratives/${narrative.id}/history`}
                  value={`/dashboard/techniques/narratives/${narrative.id}/history`}
                  label={t_i18n('History')}
                />
              </Tabs>
            </Box>
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
                element={
                  <div key={forceUpdate}>
                    <NarrativeKnowledge narrative={narrative} />
                  </div>
                }
              />
              <Route
                path="/content/*"
                element={
                  <StixCoreObjectContentRoot
                    stixCoreObject={narrative}
                  />
                }
              />
              <Route
                path="/analyses"
                element={
                  <StixCoreObjectOrStixCoreRelationshipContainers stixDomainObjectOrStixCoreRelationship={narrative} />
                }
              />
              <Route
                path="/files"
                element={
                  <FileManager
                    id={narrativeId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={narrative}
                  />
                }
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
  const { narrativeId } = useParams() as { narrativeId: string; };
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
