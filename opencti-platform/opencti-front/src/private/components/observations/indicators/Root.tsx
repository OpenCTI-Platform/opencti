import React, { Suspense, useMemo } from 'react';
import { Link, Route, Routes, useLocation, useParams } from 'react-router-dom';
import { graphql, PreloadedQuery, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { RootIndicatorQuery } from '@components/observations/indicators/__generated__/RootIndicatorQuery.graphql';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import { RootIndicatorSubscription } from '@components/observations/indicators/__generated__/RootIndicatorSubscription.graphql';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import Indicator from './Indicator';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import IndicatorEntities from './IndicatorEntities';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';
import FileManager from '../../common/files/FileManager';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import IndicatorPopover from './IndicatorPopover';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import IndicatorEdition from './IndicatorEdition';
import useHelper from '../../../../utils/hooks/useHelper';

const subscription = graphql`
  subscription RootIndicatorSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Indicator {
        ...Indicator_indicator
        ...IndicatorEditionContainer_indicator
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const indicatorQuery = graphql`
  query RootIndicatorQuery($id: String!) {
    indicator(id: $id) {
      id
      draftVersion {
        draft_id
        draft_operation
      }
      standard_id
      entity_type
      name
      pattern
      ...Indicator_indicator
      ...IndicatorDetails_indicator
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

type RootIndicatorProps = {
  indicatorId: string;
  queryRef: PreloadedQuery<RootIndicatorQuery>;
};

const RootIndicator = ({ indicatorId, queryRef }: RootIndicatorProps) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootIndicatorSubscription>>(() => ({
    subscription,
    variables: { id: indicatorId },
  }), [indicatorId]);

  const location = useLocation();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const { t_i18n } = useFormatter();
  useSubscription<RootIndicatorSubscription>(subConfig);

  const {
    indicator,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootIndicatorQuery>(indicatorQuery, queryRef);

  const { forceUpdate } = useForceUpdate();
  const link = `/dashboard/observations/indicators/${indicatorId}/knowledge`;
  const paddingRight = getPaddingRight(location.pathname, indicatorId, '/dashboard/observations/indicators', false);
  return (
    <>
      {indicator ? (
        <div style={{ paddingRight }}>
          <Breadcrumbs elements={[
            { label: t_i18n('Observations') },
            { label: t_i18n('Indicators'), link: '/dashboard/observations/indicators' },
            { label: (indicator.name ?? indicator.pattern ?? ''), current: true },
          ]}
          />
          <StixDomainObjectHeader
            entityType="Indicator"
            stixDomainObject={indicator}
            PopoverComponent={<IndicatorPopover id={indicator.id}/>}
            EditComponent={isFABReplaced && (
              <Security needs={[KNOWLEDGE_KNUPDATE]}>
                <IndicatorEdition indicatorId={indicator.id} />
              </Security>
            )}
            noAliases={true}
            enableEnrollPlaybook={true}
          />
          <Box
            sx={{
              borderBottom: 1,
              borderColor: 'divider',
              marginBottom: 3,
            }}
          >
            <Tabs
              value={getCurrentTab(location.pathname, indicator.id, '/dashboard/observations/indicators')}
            >
              <Tab
                component={Link}
                to={`/dashboard/observations/indicators/${indicator.id}`}
                value={`/dashboard/observations/indicators/${indicator.id}`}
                label={t_i18n('Overview')}
              />
              <Tab
                component={Link}
                to={`/dashboard/observations/indicators/${indicator.id}/knowledge`}
                value={`/dashboard/observations/indicators/${indicator.id}/knowledge`}
                label={t_i18n('Knowledge')}
              />
              <Tab
                component={Link}
                to={`/dashboard/observations/indicators/${indicator.id}/content`}
                value={`/dashboard/observations/indicators/${indicator.id}/content`}
                label={t_i18n('Content')}
              />
              <Tab
                component={Link}
                to={`/dashboard/observations/indicators/${indicator.id}/analyses`}
                value={`/dashboard/observations/indicators/${indicator.id}/analyses`}
                label={t_i18n('Analyses')}
              />
              <Tab
                component={Link}
                to={`/dashboard/observations/indicators/${indicator.id}/sightings`}
                value={`/dashboard/observations/indicators/${indicator.id}/sightings`}
                label={t_i18n('Sightings')}
              />
              <Tab
                component={Link}
                to={`/dashboard/observations/indicators/${indicator.id}/files`}
                value={`/dashboard/observations/indicators/${indicator.id}/files`}
                label={t_i18n('Data')}
              />
              <Tab
                component={Link}
                to={`/dashboard/observations/indicators/${indicator.id}/history`}
                value={`/dashboard/observations/indicators/${indicator.id}/history`}
                label={t_i18n('History')}
              />
            </Tabs>
          </Box>
          <Routes>
            <Route
              path="/"
              element={(<Indicator indicatorData={indicator}/>)}
            />
            <Route
              path="/content/*"
              element={
                <StixCoreObjectContentRoot
                  stixCoreObject={indicator}
                />
              }
            />
            <Route
              path="/analyses"
              element={(
                <StixCoreObjectOrStixCoreRelationshipContainers
                  stixDomainObjectOrStixCoreRelationship={indicator}
                />
              )}
            />
            <Route
              path="/sightings"
              element={(
                <EntityStixSightingRelationships
                  entityId={indicatorId}
                  entityLink={link}
                  noPadding={true}
                  isTo={false}
                  stixCoreObjectTypes={[
                    'Region',
                    'Country',
                    'City',
                    'Sector',
                    'Organization',
                    'Individual',
                    'System',
                  ]}
                />
              )}
            />
            <Route
              path="/files"
              element={(
                <FileManager
                  id={indicatorId}
                  connectorsImport={connectorsForImport}
                  connectorsExport={connectorsForExport}
                  entity={indicator}
                />
              )}
            />
            <Route
              path="/history"
              element={(
                <StixCoreObjectHistory
                  stixCoreObjectId={indicatorId}
                />
              )}
            />
            <Route
              path="/knowledge"
              element={(
                <div key={forceUpdate}>
                  <IndicatorEntities
                    indicatorId={indicatorId}
                    relationshipType={undefined}
                    defaultStartTime={undefined}
                    defaultStopTime={undefined}
                  />
                </div>
              )}
            />
            <Route
              path="/knowledge/relations/:relationId"
              element={(
                <StixCoreRelationship
                  entityId={indicatorId}
                />
              )}
            />
            <Route
              path="/knowledge/sightings/:sightingId"
              element={(
                <StixSightingRelationship
                  entityId={indicatorId}
                  paddingRight
                />
              )}
            />
          </Routes>
        </div>
      ) : (
        <ErrorNotFound />
      )}
    </>
  );
};

const Root = () => {
  const { indicatorId } = useParams() as { indicatorId: string; };
  const queryRef = useQueryLoading<RootIndicatorQuery>(indicatorQuery, {
    id: indicatorId,
  });

  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootIndicator indicatorId={indicatorId} queryRef={queryRef} />
        </Suspense>
      )}
    </>
  );
};

export default Root;
