/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Route, Switch, useParams } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import TopBar from '../../nav/TopBar';
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
      name
      x_opencti_graph_data
      ...DataSource_dataSource
      ...DataSourceKnowledge_dataSource
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
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
  const data = usePreloadedQuery(dataSourceQuery, queryRef);
  const { dataSource, connectorsForImport, connectorsForExport, settings } = data;
  return (
    <div>
      {dataSource ? (
        <Switch>
          <Route
            exact
            path="/dashboard/techniques/data_sources/:dataSourceId"
            render={() => <DataSource data={dataSource} />}
          />
          <Route
            path="/dashboard/techniques/data_sources/:dataSourceId/knowledge"
            render={(routeProps: any) => (
              <DataSourceKnowledgeComponent
                {...routeProps}
                data={dataSource}
                enableReferences={settings.platform_enable_reference?.includes(
                  'Data-Source',
                )}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/techniques/data_sources/:dataSourceId/files"
            render={(routeProps: any) => (
              <React.Fragment>
                <StixDomainObjectHeader
                  entityType={'Data-Source'}
                  disableSharing={true}
                  stixDomainObject={dataSource}
                  PopoverComponent={<DataSourcePopover id={dataSource.id} />}
                />
                <FileManager
                  {...routeProps}
                  id={dataSourceId}
                  connectorsImport={connectorsForImport}
                  connectorsExport={connectorsForExport}
                  entity={dataSource}
                />
              </React.Fragment>
            )}
          />
          <Route
            exact
            path="/dashboard/techniques/data_sources/:dataSourceId/history"
            render={(routeProps: any) => (
              <React.Fragment>
                <StixDomainObjectHeader
                  entityType={'Data-Source'}
                  disableSharing={true}
                  stixDomainObject={dataSource}
                  PopoverComponent={<DataSourcePopover id={dataSource.id} />}
                />
                <StixCoreObjectHistory
                  {...routeProps}
                  stixCoreObjectId={dataSourceId}
                />
              </React.Fragment>
            )}
          />
        </Switch>
      ) : (
        <ErrorNotFound />
      )}
    </div>
  );
};

const RootDataSource = () => {
  const { dataSourceId } = useParams() as { dataSourceId: string };
  const queryRef = useQueryLoading<RootDataSourceQuery>(dataSourceQuery, {
    id: dataSourceId,
  });
  return (
    <>
      <TopBar />
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
