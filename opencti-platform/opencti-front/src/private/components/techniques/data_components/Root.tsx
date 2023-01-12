/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Route, Switch, useParams } from 'react-router-dom';
import { graphql, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import { QueryRenderer } from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import DataComponent from './DataComponent';
import DataComponentPopover from './DataComponentPopover';
import FileManager from '../../common/files/FileManager';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import { RootDataComponentQuery$data } from './__generated__/RootDataComponentQuery.graphql';
import DataComponentKnowledge from './DataComponentKnowledge';
import { RootDataComponentSubscription } from './__generated__/RootDataComponentSubscription.graphql';

const subscription = graphql`
  subscription RootDataComponentSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on DataComponent {
        ...DataComponent_dataComponent
        ...DataComponentEditionOverview_dataComponent
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const dataComponentQuery = graphql`
  query RootDataComponentQuery($id: String!) {
    dataComponent(id: $id) {
      id
      name
      x_opencti_graph_data
      ...DataComponent_dataComponent
      ...DataComponentKnowledge_dataComponent
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

const RootDataComponent = () => {
  const { dataComponentId } = useParams() as { dataComponentId: string };
  const subConfig = useMemo<
  GraphQLSubscriptionConfig<RootDataComponentSubscription>
  >(
    () => ({
      subscription,
      variables: { id: dataComponentId },
    }),
    [dataComponentId],
  );
  useSubscription(subConfig);
  return (
    <div>
      <TopBar />
      <QueryRenderer
        query={dataComponentQuery}
        variables={{ id: dataComponentId }}
        render={({ props }: { props: RootDataComponentQuery$data }) => {
          if (props) {
            if (props.dataComponent) {
              return (
                <Switch>
                  <Route
                    exact
                    path="/dashboard/techniques/data_components/:dataComponentId"
                    render={(routeProps: any) => (
                      <DataComponent
                        {...routeProps}
                        data={props.dataComponent}
                      />
                    )}
                  />
                  <Route
                    path="/dashboard/techniques/data_components/:dataComponentId/knowledge"
                    render={(routeProps: any) => (
                      <DataComponentKnowledge
                        {...routeProps}
                        data={props.dataComponent}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/techniques/data_components/:dataComponentId/files"
                    render={(routeProps: any) => (
                      <React.Fragment>
                        <StixDomainObjectHeader
                          stixDomainObject={props.dataComponent}
                          PopoverComponent={
                            <DataComponentPopover
                              dataComponentId={dataComponentId}
                            />
                          }
                        />
                        <FileManager
                          {...routeProps}
                          id={dataComponentId}
                          connectorsImport={props.connectorsForImport}
                          connectorsExport={props.connectorsForExport}
                          entity={props.dataComponent}
                        />
                      </React.Fragment>
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/techniques/data_components/:dataComponentId/history"
                    render={(routeProps: any) => (
                      <React.Fragment>
                        <StixDomainObjectHeader
                          stixDomainObject={props.dataComponent}
                          PopoverComponent={
                            <DataComponentPopover
                              dataComponentId={dataComponentId}
                            />
                          }
                        />
                        <StixCoreObjectHistory
                          {...routeProps}
                          stixCoreObjectId={dataComponentId}
                        />
                      </React.Fragment>
                    )}
                  />
                </Switch>
              );
            }
            return <ErrorNotFound />;
          }
          return <Loader />;
        }}
      />
    </div>
  );
};

export default RootDataComponent;
