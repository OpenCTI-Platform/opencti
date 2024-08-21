/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Link, Route, Routes, useParams, useLocation } from 'react-router-dom';
import { graphql, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import StixCoreObjectContentRoot from '@components/common/stix_core_objects/StixCoreObjectContentRoot';
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
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';

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
              const paddingRight = getPaddingRight(location.pathname, dataComponent.id, '/dashboard/techniques/data_components', false);
              return (
                <div style={{ paddingRight }}>
                  <Breadcrumbs variant="object" elements={[
                    { label: t_i18n('Techniques') },
                    { label: t_i18n('Data components'), link: '/dashboard/techniques/data_components' },
                    { label: dataComponent.name, current: true },
                  ]}
                  />
                  <StixDomainObjectHeader
                    entityType="Data-Component"
                    stixDomainObject={props.dataComponent}
                    PopoverComponent={
                      <DataComponentPopover dataComponentId={dataComponentId}/>
                    }
                    noAliases={true}
                  />
                  <Box
                    sx={{
                      borderBottom: 1,
                      borderColor: 'divider',
                      marginBottom: 4,
                    }}
                  >
                    <Tabs
                      value={getCurrentTab(location.pathname, dataComponent.id, '/dashboard/arsenal/techniques')}
                    >
                      <Tab
                        component={Link}
                        to={`/dashboard/techniques/data_components/${dataComponent.id}`}
                        value={`/dashboard/techniques/data_components/${dataComponent.id}`}
                        label={t_i18n('Overview')}
                      />
                      <Tab
                        component={Link}
                        to={`/dashboard/techniques/data_components/${dataComponent.id}/content`}
                        value={`/dashboard/techniques/data_components/${dataComponent.id}/content`}
                        label={t_i18n('Content')}
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
                  <Routes>
                    <Route
                      path="/"
                      element={
                        <DataComponent dataComponentData={dataComponent}/>
                      }
                    />
                    <Route
                      path="/knowledge/*"
                      element={
                        <DataComponentKnowledge data={dataComponent}/>
                      }
                    />
                    <Route
                      path="/content/*"
                      element={
                        <StixCoreObjectContentRoot
                          stixCoreObject={dataComponent}
                        />
                      }
                    />
                    <Route
                      path="/files"
                      element={
                        <FileManager
                          id={dataComponentId}
                          connectorsImport={props.connectorsForImport}
                          connectorsExport={props.connectorsForExport}
                          entity={dataComponent}
                        />
                      }
                    />
                    <Route
                      path="/history"
                      element={
                        <StixCoreObjectHistory stixCoreObjectId={dataComponentId}/>
                      }
                    />
                  </Routes>
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
