import React, { useMemo, Suspense } from 'react';
import { Route, Routes, Link, Navigate, useLocation, useParams } from 'react-router-dom';
import { graphql, useSubscription, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import ToolEdition from '@components/arsenal/tools/ToolEdition';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import Tool from './Tool';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';
import { RootToolQuery } from './__generated__/RootToolQuery.graphql';
import { RootToolSubscription } from './__generated__/RootToolSubscription.graphql';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import ToolKnowledge from './ToolKnowledge';
import ToolDeletion from './ToolDeletion';

const subscription = graphql`
  subscription RootToolSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Tool {
        ...Tool_tool
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...PictureManagementViewer_entity
    }
  }
`;

const toolQuery = graphql`
  query RootToolQuery($id: String!) {
    tool(id: $id) {
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
      ...StixCoreObjectKnowledgeBar_stixCoreObject
      ...Tool_tool
      ...ToolKnowledge_tool
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

type RootToolProps = {
  toolId: string;
  queryRef: PreloadedQuery<RootToolQuery>;
};

const RootTool = ({ queryRef, toolId }: RootToolProps) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootToolSubscription>>(() => ({
    subscription,
    variables: { id: toolId },
  }), [toolId]);

  const location = useLocation();
  const { t_i18n } = useFormatter();
  useSubscription<RootToolSubscription>(subConfig);

  const {
    tool,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootToolQuery>(toolQuery, queryRef);

  const { forceUpdate } = useForceUpdate();

  const paddingRight = getPaddingRight(location.pathname, toolId, '/dashboard/arsenal/tools');
  const link = `/dashboard/arsenal/tools/${toolId}/knowledge`;
  return (
    <>
      {tool ? (
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
                    'attack_patterns',
                    'vulnerabilities',
                    'indicators',
                    'observables',
                    'sightings',
                  ]}
                  data={tool}
                />
              }
            />
          </Routes>
          <div style={{ paddingRight }}>
            <Breadcrumbs elements={[
              { label: t_i18n('Arsenal') },
              { label: t_i18n('Tools'), link: '/dashboard/arsenal/tools' },
              { label: tool.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="Tool"
              stixDomainObject={tool}
              EditComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <ToolEdition toolId={tool.id} />
                </Security>
              )}
              DeleteComponent={({ isOpen, onClose }: { isOpen: boolean, onClose: () => void }) => (
                <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                  <ToolDeletion id={tool.id} isOpen={isOpen} handleClose={onClose} />
                </Security>
              )}
              enableEnricher={true}
              enableQuickSubscription={true}
              redirectToContent={true}
            />
            <Box
              sx={{
                borderBottom: 1,
                borderColor: 'divider',
                marginBottom: 3,
              }}
            >
              <Tabs
                value={getCurrentTab(location.pathname, tool.id, '/dashboard/arsenal/tools')}
              >
                <Tab
                  component={Link}
                  to={`/dashboard/arsenal/tools/${tool.id}`}
                  value={`/dashboard/arsenal/tools/${tool.id}`}
                  label={t_i18n('Overview')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/arsenal/tools/${tool.id}/knowledge/overview`}
                  value={`/dashboard/arsenal/tools/${tool.id}/knowledge`}
                  label={t_i18n('Knowledge')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/arsenal/tools/${tool.id}/content`}
                  value={`/dashboard/arsenal/tools/${tool.id}/content`}
                  label={t_i18n('Content')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/arsenal/tools/${tool.id}/analyses`}
                  value={`/dashboard/arsenal/tools/${tool.id}/analyses`}
                  label={t_i18n('Analyses')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/arsenal/tools/${tool.id}/files`}
                  value={`/dashboard/arsenal/tools/${tool.id}/files`}
                  label={t_i18n('Data')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/arsenal/tools/${tool.id}/history`}
                  value={`/dashboard/arsenal/tools/${tool.id}/history`}
                  label={t_i18n('History')}
                />
              </Tabs>
            </Box>
            <Routes>
              <Route
                path="/"
                element={ (
                  <Tool toolData={tool} />
                )}
              />
              <Route
                path="/knowledge"
                element={
                  <Navigate
                    replace={true}
                    to={`/dashboard/arsenal/tools/${toolId}/knowledge/overview`}
                  />
                }
              />
              <Route
                path="/knowledge/*"
                element={
                  <div key={forceUpdate}>
                    <ToolKnowledge toolData={tool} />
                  </div>
                }
              />
              <Route
                path="/content/*"
                element={
                  <StixCoreObjectContentRoot
                    stixCoreObject={tool}
                  />
                }
              />
              <Route
                path="/analyses/*"
                element={(
                  <StixCoreObjectOrStixCoreRelationshipContainers
                    stixDomainObjectOrStixCoreRelationship={tool}
                  />
                )}
              />
              <Route
                path="/files"
                element={(
                  <FileManager
                    id={toolId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={tool}
                  />
                )}
              />
              <Route
                path="/history"
                element={ (
                  <StixCoreObjectHistory
                    stixCoreObjectId={toolId}
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
  const { toolId } = useParams() as { toolId: string; };
  const queryRef = useQueryLoading<RootToolQuery>(toolQuery, {
    id: toolId,
  });

  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootTool queryRef={queryRef} toolId={toolId} />
        </Suspense>
      )}
    </>
  );
};

export default Root;
