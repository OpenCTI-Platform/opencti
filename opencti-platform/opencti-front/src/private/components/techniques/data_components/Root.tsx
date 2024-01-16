/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Link, Route, Switch, useParams } from 'react-router-dom';
import { graphql, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { useLocation } from 'react-router-dom-v5-compat';
import { QueryRenderer } from '../../../../relay/environment';
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
import { useFormatter } from '../../../../components/i18n';

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
      standard_id
      entity_type
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
  const location = useLocation();
  const { t_i18n } = useFormatter();
  return (
    <>
      <QueryRenderer
        query={dataComponentQuery}
        variables={{ id: dataComponentId }}
        render={({ props }: { props: RootDataComponentQuery$data }) => {
          if (props) {
            if (props.dataComponent) {
              const { dataComponent } = props;
              return (
                <div
                  style={{
                    paddingRight: location.pathname.includes(
                      `/dashboard/techniques/data_components/${dataComponent.id}/knowledge`,
                    )
                      ? 200
                      : 0,
                  }}
                >
                  <StixDomainObjectHeader
                    entityType="Data-Component"
                    stixDomainObject={props.dataComponent}
                    PopoverComponent={
                      <DataComponentPopover dataComponentId={dataComponentId} />
                    }
                  />
                  <Box
                    sx={{
                      borderBottom: 1,
                      borderColor: 'divider',
                      marginBottom: 4,
                    }}
                  >
                    <Tabs
                      value={
                        location.pathname.includes(
                          `/dashboard/techniques/data_components/${dataComponent.id}/knowledge`,
                        )
                          ? `/dashboard/techniques/data_components/${dataComponent.id}/knowledge`
                          : location.pathname
                      }
                    >
                      <Tab
                        component={Link}
                        to={`/dashboard/techniques/data_components/${dataComponent.id}`}
                        value={`/dashboard/techniques/data_components/${dataComponent.id}`}
                        label={t_i18n('Overview')}
                      />
                      <Tab
                        component={Link}
                        to={`/dashboard/techniques/data_components/${dataComponent.id}/files`}
                        value={`/dashboard/techniques/data_components/${dataComponent.id}/files`}
                        label={t_i18n('Data')}
                      />
                      <Tab
                        component={Link}
                        to={`/dashboard/techniques/data_components/${dataComponent.id}/history`}
                        value={`/dashboard/techniques/data_components/${dataComponent.id}/history`}
                        label={t_i18n('History')}
                      />
                    </Tabs>
                  </Box>
                  <Switch>
                    <Route
                      exact
                      path="/dashboard/techniques/data_components/:dataComponentId"
                      render={(routeProps: any) => (
                        <DataComponent {...routeProps} data={dataComponent} />
                      )}
                    />
                    <Route
                      path="/dashboard/techniques/data_components/:dataComponentId/knowledge"
                      render={(routeProps: any) => (
                        <DataComponentKnowledge
                          {...routeProps}
                          data={dataComponent}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/techniques/data_components/:dataComponentId/files"
                      render={(routeProps: any) => (
                        <FileManager
                          {...routeProps}
                          id={dataComponentId}
                          connectorsImport={props.connectorsForImport}
                          connectorsExport={props.connectorsForExport}
                          entity={dataComponent}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/techniques/data_components/:dataComponentId/history"
                      render={(routeProps: any) => (
                        <StixCoreObjectHistory
                          {...routeProps}
                          stixCoreObjectId={dataComponentId}
                        />
                      )}
                    />
                  </Switch>
                </div>
              );
            }
            return <ErrorNotFound />;
          }
          return <Loader />;
        }}
      />
    </>
  );
};

export default RootDataComponent;
