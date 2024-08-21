import React, { useMemo, Suspense } from 'react';
import { Route, Routes, Link, Navigate, useLocation, useParams } from 'react-router-dom';
import { graphql, useSubscription, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import StixCoreObjectSimulationResult from '../../common/stix_core_objects/StixCoreObjectSimulationResult';
import IntrusionSet from './IntrusionSet';
import IntrusionSetKnowledge from './IntrusionSetKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import IntrusionSetPopover from './IntrusionSetPopover';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';
import BulkRelationDialogContainer from '../../common/bulk/dialog/BulkRelationDialogContainer';
import { RootIntrusionSetQuery } from './__generated__/RootIntrusionSetQuery.graphql';
import { RootIntrusionSetSubscription } from './__generated__/RootIntrusionSetSubscription.graphql';

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
      standard_id
      entity_type
      name
      aliases
      objectMarking {
        id
      }
      x_opencti_graph_data
      stixCoreObjectsDistribution(field: "entity_type", operation: count) {
        label
        value
      }
      ...IntrusionSet_intrusionSet
      ...IntrusionSetKnowledge_intrusionSet
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...PictureManagementViewer_entity
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

  const { forceUpdate, handleForceUpdate } = useForceUpdate();

  const isOverview = location.pathname === `/dashboard/threats/intrusion_sets/${intrusionSetId}`;
  const isKnowledge = location.pathname.startsWith(`/dashboard/threats/intrusion_sets/${intrusionSetId}/knowledge`);
  const paddingRight = getPaddingRight(location.pathname, intrusionSetId, '/dashboard/threats/intrusion_sets');
  const link = `/dashboard/threats/intrusion_sets/${intrusionSetId}/knowledge`;
  return (
    <>
      {intrusionSet ? (
        <>
          <Routes>
            <Route
              path="/knowledge/*"
              element={
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
                  ]}
                  stixCoreObjectsDistribution={intrusionSet.stixCoreObjectsDistribution}
                  attribution={['Threat-Actor-Individual', 'Threat-Actor-Group']}
                />
              }
            />
          </Routes>
          <div style={{ paddingRight }} data-testid="intrusionSet-details-page">
            <Breadcrumbs variant="object" elements={[
              { label: t_i18n('Threats') },
              { label: t_i18n('Intrusion sets'), link: '/dashboard/threats/intrusion_sets' },
              { label: intrusionSet.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="Intrusion-Set"
              stixDomainObject={intrusionSet}
              PopoverComponent={<IntrusionSetPopover />}
              enableQuickSubscription={true}
              enableAskAi={true}
            />
            <Box
              sx={{
                borderBottom: 1,
                borderColor: 'divider',
                marginBottom: 4,
                display: 'flex',
                justifyContent: 'space-between',
                alignItem: 'center',
              }}
            >
              <Tabs
                value={getCurrentTab(location.pathname, intrusionSet.id, '/dashboard/threats/intrusion_sets')}
              >
                <Tab
                  component={Link}
                  to={`/dashboard/threats/intrusion_sets/${intrusionSet.id}`}
                  value={`/dashboard/threats/intrusion_sets/${intrusionSet.id}`}
                  label={t_i18n('Overview')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/threats/intrusion_sets/${intrusionSet.id}/knowledge/overview`}
                  value={`/dashboard/threats/intrusion_sets/${intrusionSet.id}/knowledge`}
                  label={t_i18n('Knowledge')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/threats/intrusion_sets/${intrusionSet.id}/content`}
                  value={`/dashboard/threats/intrusion_sets/${intrusionSet.id}/content`}
                  label={t_i18n('Content')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/threats/intrusion_sets/${intrusionSet.id}/analyses`}
                  value={`/dashboard/threats/intrusion_sets/${intrusionSet.id}/analyses`}
                  label={t_i18n('Analyses')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/threats/intrusion_sets/${intrusionSet.id}/files`}
                  value={`/dashboard/threats/intrusion_sets/${intrusionSet.id}/files`}
                  label={t_i18n('Data')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/threats/intrusion_sets/${intrusionSet.id}/history`}
                  value={`/dashboard/threats/intrusion_sets/${intrusionSet.id}/history`}
                  label={t_i18n('History')}
                />
              </Tabs>
              {isKnowledge && (
                <BulkRelationDialogContainer
                  stixDomainObjectId={intrusionSet.id}
                  stixDomainObjectName={intrusionSet.name}
                  stixDomainObjectType="Intrusion-Set"
                  handleRefetch={handleForceUpdate}
                />
              )}
              {isOverview && (
                <StixCoreObjectSimulationResult id={intrusionSet.id} type="threat" />
              )}
            </Box>
            <Routes>
              <Route
                path="/"
                element={
                  <IntrusionSet intrusionSetData={intrusionSet} />
                }
              />
              <Route
                path="/knowledge"
                element={
                  <Navigate to={`/dashboard/threats/intrusion_sets/${intrusionSetId}/knowledge/overview`} replace={true} />
                }
              />
              <Route
                path="/knowledge/*"
                element={
                  <div data-testid="instrusionSet-knowledge" key={forceUpdate}>
                    <IntrusionSetKnowledge intrusionSet={intrusionSet} />
                  </div>
                }
              />
              <Route
                path="/content/*"
                element={
                  <StixCoreObjectContentRoot
                    stixCoreObject={intrusionSet}
                  />
                }
              />
              <Route
                path="/analyses"
                element={
                  <StixCoreObjectOrStixCoreRelationshipContainers stixDomainObjectOrStixCoreRelationship={intrusionSet} />
                }
              />
              <Route
                path="/files"
                element={
                  <FileManager
                    id={intrusionSetId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={intrusionSet}
                  />
                }
              />
              <Route
                path="/history"
                element={
                  <StixCoreObjectHistory stixCoreObjectId={intrusionSetId} />
                }
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
  const { intrusionSetId } = useParams() as { intrusionSetId: string; };
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
