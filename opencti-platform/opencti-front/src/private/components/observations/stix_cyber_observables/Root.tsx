import React, { Suspense, useMemo } from 'react';
import { Route, Routes, Link, useLocation, useParams } from 'react-router-dom';
import { graphql, useSubscription, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import { RootStixCyberObservableQuery } from '@components/observations/stix_cyber_observables/__generated__/RootStixCyberObservableQuery.graphql';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import { RootStixCyberObservableSubscription } from '@components/observations/stix_cyber_observables/__generated__/RootStixCyberObservableSubscription.graphql';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import StixCyberObservable from './StixCyberObservable';
import StixCyberObservableKnowledge from './StixCyberObservableKnowledge';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCyberObservableHeader from './StixCyberObservableHeader';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import FileManager from '../../common/files/FileManager';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';
import CreateRelationshipContextProvider from '../../common/menus/CreateRelationshipContextProvider';

const subscription = graphql`
  subscription RootStixCyberObservableSubscription($id: ID!) {
    stixCyberObservable(id: $id) {
      ...StixCyberObservable_stixCyberObservable
      ...StixCyberObservableEditionContainer_stixCyberObservable
      ...StixCyberObservableKnowledge_stixCyberObservable
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const stixCyberObservableQuery = graphql`
  query RootStixCyberObservableQuery($id: String!) {
    stixCyberObservable(id: $id) {
      id
      standard_id
      entity_type
      observable_value
      ...StixCyberObservable_stixCyberObservable
      ...StixCyberObservableHeader_stixCyberObservable
      ...StixCyberObservableDetails_stixCyberObservable
      ...StixCyberObservableIndicators_stixCyberObservable
      ...StixCyberObservableKnowledge_stixCyberObservable
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

type RootStixCyberObservableProps = {
  observableId: string;
  queryRef: PreloadedQuery<RootStixCyberObservableQuery>
};

const RootStixCyberObservable = ({ observableId, queryRef }: RootStixCyberObservableProps) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootStixCyberObservableSubscription>>(() => ({
    subscription,
    variables: { id: observableId },
  }), [observableId]);

  const location = useLocation();
  const { t_i18n } = useFormatter();
  useSubscription<RootStixCyberObservableSubscription>(subConfig);

  const {
    stixCyberObservable,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootStixCyberObservableQuery>(stixCyberObservableQuery, queryRef);

  const { forceUpdate } = useForceUpdate();

  const paddingRight = getPaddingRight(location.pathname, observableId, '/dashboard/observations/observables', false);
  const link = `/dashboard/observations/observables/${observableId}/knowledge`;

  return (
    <CreateRelationshipContextProvider>
      {stixCyberObservable ? (
        <div style={{ paddingRight }}>
          <Breadcrumbs elements={[
            { label: t_i18n('Observations') },
            { label: t_i18n('Observables'), link: '/dashboard/observations/observables' },
            { label: stixCyberObservable.observable_value, current: true },
          ]}
          />
          <StixCyberObservableHeader
            stixCyberObservable={stixCyberObservable}
            isArtifact={false}
          />
          <Box
            sx={{
              borderBottom: 1,
              borderColor: 'divider',
              marginBottom: 3,
            }}
          >
            <Tabs
              value={getCurrentTab(location.pathname, stixCyberObservable.id, '/dashboard/observations/observables')}
            >
              <Tab
                component={Link}
                to={`/dashboard/observations/observables/${stixCyberObservable.id}`}
                value={`/dashboard/observations/observables/${stixCyberObservable.id}`}
                label={t_i18n('Overview')}
              />
              <Tab
                component={Link}
                to={`/dashboard/observations/observables/${stixCyberObservable.id}/knowledge`}
                value={`/dashboard/observations/observables/${stixCyberObservable.id}/knowledge`}
                label={t_i18n('Knowledge')}
              />
              <Tab
                component={Link}
                to={`/dashboard/observations/observables/${stixCyberObservable.id}/content`}
                value={`/dashboard/observations/observables/${stixCyberObservable.id}/content`}
                label={t_i18n('Content')}
              />
              <Tab
                component={Link}
                to={`/dashboard/observations/observables/${stixCyberObservable.id}/analyses`}
                value={`/dashboard/observations/observables/${stixCyberObservable.id}/analyses`}
                label={t_i18n('Analyses')}
              />
              <Tab
                component={Link}
                to={`/dashboard/observations/observables/${stixCyberObservable.id}/sightings`}
                value={`/dashboard/observations/observables/${stixCyberObservable.id}/sightings`}
                label={t_i18n('Sightings')}
              />
              <Tab
                component={Link}
                to={`/dashboard/observations/observables/${stixCyberObservable.id}/files`}
                value={`/dashboard/observations/observables/${stixCyberObservable.id}/files`}
                label={t_i18n('Data')}
              />
              <Tab
                component={Link}
                to={`/dashboard/observations/observables/${stixCyberObservable.id}/history`}
                value={`/dashboard/observations/observables/${stixCyberObservable.id}/history`}
                label={t_i18n('History')}
              />
            </Tabs>
          </Box>
          <Routes>
            <Route
              path="/"
              element={
                <StixCyberObservable
                  stixCyberObservableData={stixCyberObservable}
                />
              }
            />
            <Route
              path="/knowledge"
              element={
                <div key={forceUpdate}>
                  <StixCyberObservableKnowledge
                    stixCyberObservable={stixCyberObservable}
                  />
                </div>
              }
            />
            <Route
              path="/content/*"
              element={
                <StixCoreObjectContentRoot
                  stixCoreObject={stixCyberObservable}
                />
              }
            />
            <Route
              path="/analyses"
              element={
                <StixCoreObjectOrStixCoreRelationshipContainers
                  stixDomainObjectOrStixCoreRelationship={
                    stixCyberObservable
                  }
                />
              }
            />
            <Route
              path="/sightings"
              element={
                <EntityStixSightingRelationships
                  entityId={observableId}
                  entityLink={link}
                  noPadding={true}
                  isTo={true}
                  stixCoreObjectTypes={[
                    'Region',
                    'Country',
                    'City',
                    'Position',
                    'Sector',
                    'Organization',
                    'Individual',
                    'System',
                  ]}
                />
              }
            />
            <Route
              path="/files"
              element={
                <FileManager
                  id={observableId}
                  connectorsImport={connectorsForImport}
                  connectorsExport={connectorsForExport}
                  entity={stixCyberObservable}
                />
              }
            />
            <Route
              path="/history"
              element={
                <StixCoreObjectHistory
                  stixCoreObjectId={observableId}
                />
              }
            />
            <Route
              path="/knowledge/relations/:relationId"
              element={
                <StixCoreRelationship
                  entityId={observableId}
                />
              }
            />
            <Route
              path="/sightings/:sightingId"
              element={
                <StixSightingRelationship
                  entityId={observableId}
                  paddingRight
                />
              }
            />
          </Routes>
        </div>
      ) : (
        <ErrorNotFound />
      )}
    </CreateRelationshipContextProvider>
  );
};

const Root = () => {
  const { observableId } = useParams() as { observableId: string; };
  const queryRef = useQueryLoading<RootStixCyberObservableQuery>(stixCyberObservableQuery, { id: observableId });

  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootStixCyberObservable queryRef={queryRef} observableId={observableId} />
        </Suspense>
      )}
    </>
  );
};

export default Root;
