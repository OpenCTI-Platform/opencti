/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Route, Redirect, Switch, useParams } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import TopBar from '../../nav/TopBar';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import useAuth from '../../../../utils/hooks/useAuth';
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
    connectorsForExport {
      ...FileManager_connectorsExport
    }
    settings {
      platform_enable_reference
    }
  }
`;

const RootDataSourceComponent = ({ queryRef }) => {
  const { me } = useAuth();
  const { dataSourceId } = useParams() as { dataSourceId: string };

  const link = `/dashboard/techniques/data_sources/${dataSourceId}/knowledge`;
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootDataSourcesSubscription>>(() => ({
    subscription,
    variables: { id: dataSourceId },
  }), [dataSourceId]);
  useSubscription(subConfig);

  const data = usePreloadedQuery(dataSourceQuery, queryRef);
  const { dataSource, connectorsForExport } = data;

  return (
    <div>
      <TopBar me={me} />
      <Route path="/dashboard/techniques/data_sources/:dataSourceId/knowledge">
        <StixCoreObjectKnowledgeBar
          stixCoreObjectLink={link}
          availableSections={[
            'cities',
            'organizations',
            'threat_actors',
            'intrusion_sets',
            'campaigns',
            'incidents',
            'malwares',
            'attack_patterns',
            'tools',
            'observables',
          ]}
        />
      </Route>
      <>
        {dataSource ? (
          <Switch>
            <Route
              exact
              path="/dashboard/techniques/data_sources/:dataSourceId"
              render={() => (<DataSource data={dataSource} />)}
            />
            <Route
              exact
              path="/dashboard/techniques/data_sources/:dataSourceId/knowledge"
              render={() => (
                <Redirect
                  to={`/dashboard/techniques/data_sources/${dataSourceId}/knowledge/overview`}
                />
              )}
            />
            <Route
              path="/dashboard/techniques/data_sources/:dataSourceId/knowledge"
              render={() => ({ DataSourceKnowledgeComponent })}
            />
            <Route
              exact
              path="/dashboard/techniques/data_sources/:dataSourceId/analysis"
              render={(routeProps: any) => (
                <React.Fragment>
                  <StixDomainObjectHeader
                    disableSharing={true}
                    stixDomainObject={dataSource}
                    PopoverComponent={<DataSourcePopover id={dataSource.id} /> }
                  />
                  <StixCoreObjectOrStixCoreRelationshipContainers
                    {...routeProps}
                    stixDomainObjectOrStixCoreRelationship={dataSource}
                  />
                </React.Fragment>
              )}
            />
            <Route
              exact
              path="/dashboard/techniques/data_sources/:dataSourceId/sightings"
              render={(routeProps: any) => (
                <EntityStixSightingRelationships
                  entityId={dataSourceId}
                  entityLink={link}
                  noPadding={true}
                  isTo={true}
                  {...routeProps}
                />
              )}
            />
            <Route
              exact
              path="/dashboard/techniques/data_sources/:dataSourceId/files"
              render={(routeProps: any) => (
                <React.Fragment>
                  <StixDomainObjectHeader
                    disableSharing={true}
                    stixDomainObject={dataSource}
                    PopoverComponent={<DataSourcePopover id={dataSource.id} />}
                  />
                  <FileManager
                    {...routeProps}
                    id={dataSourceId}
                    connectorsImport={[]}
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
        ) : <ErrorNotFound />}
      </>
    </div>
  );
};

const RootDataSource = () => {
  const { dataSourceId } = useParams() as { dataSourceId: string };

  const queryRef = useQueryLoading<RootDataSourceQuery>(dataSourceQuery, { id: dataSourceId });
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <RootDataSourceComponent queryRef={queryRef} />
    </React.Suspense>
  ) : <Loader variant={LoaderVariant.inElement} />;
};

export default RootDataSource;
