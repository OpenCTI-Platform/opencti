/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Link, Route, Routes, useParams, useLocation } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import Box from '@mui/material/Box';
import StixCoreObjectContentRoot from '@components/common/stix_core_objects/StixCoreObjectContentRoot';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { RootDataSourceQuery } from './__generated__/RootDataSourceQuery.graphql';
import { RootDataSourcesSubscription } from './__generated__/RootDataSourcesSubscription.graphql';
import DataSourcePopover from './DataSourcePopover';
import DataSourceKnowledgeComponent from './DataSourceKnowledge';
import DataSource from './DataSource';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';

const subscription = graphql`
  subscription RootDataSourcesSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on DataSource {
        ...DataSource_dataSource
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const dataSourceQuery = graphql`
  query RootDataSourceQuery($id: String!) {
    dataSource(id: $id) {
      id
      standard_id
      entity_type
      name
      x_opencti_graph_data
      ...DataSource_dataSource
      ...DataSourceKnowledge_dataSource
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

const RootDataSourceComponent = ({ queryRef, dataSourceId }) => {
  const subConfig = useMemo<
  GraphQLSubscriptionConfig<RootDataSourcesSubscription>
  >(
    () => ({
      subscription,
      variables: { id: dataSourceId },
    }),
    [dataSourceId],
  );
  useSubscription(subConfig);
  const location = useLocation();
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery(dataSourceQuery, queryRef);
  const { dataSource, connectorsForImport, connectorsForExport, settings } = data;
  const paddingRight = getPaddingRight(location.pathname, dataSource?.id, '/dashboard/techniques/data_sources', false);
  return (
    <>
      {dataSource ? (
        <div style={{ paddingRight }}>
          <Breadcrumbs variant="object" elements={[
            { label: t_i18n('Techniques') },
            { label: t_i18n('Data sources'), link: '/dashboard/techniques/data_sources' },
            { label: dataSource.name, current: true },
          ]}
          />
          <StixDomainObjectHeader
            entityType="Data-Source"
            noAliases={true}
            stixDomainObject={dataSource}
            PopoverComponent={<DataSourcePopover id={dataSource.id}/>}
          />
          <Box
            sx={{ borderBottom: 1, borderColor: 'divider', marginBottom: 4 }}
          >
            <Tabs
              value={getCurrentTab(location.pathname, dataSource.id, '/dashboard/techniques/data_sources')}
            >
              <Tab
                component={Link}
                to={`/dashboard/techniques/data_sources/${dataSource.id}`}
                value={`/dashboard/techniques/data_sources/${dataSource.id}`}
                label={t_i18n('Overview')}
              />
              <Tab
                component={Link}
                to={`/dashboard/techniques/data_sources/${dataSource.id}/content`}
                value={`/dashboard/techniques/data_sources/${dataSource.id}/content`}
                label={t_i18n('Content')}
              />
              <Tab
                component={Link}
                to={`/dashboard/techniques/data_sources/${dataSource.id}/files`}
                value={`/dashboard/techniques/data_sources/${dataSource.id}/files`}
                label={t_i18n('Data')}
              />
              <Tab
                component={Link}
                to={`/dashboard/techniques/data_sources/${dataSource.id}/history`}
                value={`/dashboard/techniques/data_sources/${dataSource.id}/history`}
                label={t_i18n('History')}
              />
            </Tabs>
          </Box>
          <Routes>
            <Route
              path="/"
              element={
                <DataSource dataSourceData={dataSource}/>
              }
            />
            <Route
              path="/knowledge/*"
              element={
                <DataSourceKnowledgeComponent
                  data={dataSource}
                  enableReferences={settings?.platform_enable_reference?.includes(
                    'Data-Source',
                  )}
                />
              }
            />
            <Route
              path="/content/*"
              element={
                <StixCoreObjectContentRoot
                  stixCoreObject={dataSource}
                />
              }
            />
            <Route
              path="/files"
              element={
                <FileManager
                  id={dataSourceId}
                  connectorsImport={connectorsForImport}
                  connectorsExport={connectorsForExport}
                  entity={dataSource}
                />
              }
            />
            <Route
              path="/history"
              element={
                <StixCoreObjectHistory stixCoreObjectId={dataSourceId}/>
              }
            />
          </Routes>
        </div>
      ) : (
        <ErrorNotFound/>
      )}
    </>
  );
};

const RootDataSource = () => {
  const { dataSourceId } = useParams() as { dataSourceId: string };
  const queryRef = useQueryLoading<RootDataSourceQuery>(dataSourceQuery, {
    id: dataSourceId,
  });
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootDataSourceComponent
            queryRef={queryRef}
            dataSourceId={dataSourceId}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default RootDataSource;
