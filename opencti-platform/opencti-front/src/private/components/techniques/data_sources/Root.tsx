// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Route, useParams, useLocation } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import StixCoreObjectContentRoot from '@components/common/stix_core_objects/StixCoreObjectContentRoot';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixDomainObjectMain from '@components/common/stix_domain_objects/StixDomainObjectMain';
import FileManager from '../../common/files/FileManager';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { RootDataSourceQuery } from './__generated__/RootDataSourceQuery.graphql';
import { RootDataSourcesSubscription } from './__generated__/RootDataSourcesSubscription.graphql';
import DataSourceKnowledgeComponent from './DataSourceKnowledge';
import DataSource from './DataSource';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getPaddingRight } from '../../../../utils/utils';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import DataSourceEdition from './DataSourceEdition';
import DataSourceDeletion from './DataSourceDeletion';

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
      draftVersion {
        draft_id
        draft_operation
      }
      standard_id
      entity_type
      name
      x_opencti_graph_data
      currentUserAccessRight
      ...DataSource_dataSource
      ...DataSourceKnowledge_dataSource
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
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
          <Breadcrumbs elements={[
            { label: t_i18n('Techniques') },
            { label: t_i18n('Data sources'), link: '/dashboard/techniques/data_sources' },
            { label: dataSource.name, current: true },
          ]}
          />
          <StixDomainObjectHeader
            entityType="Data-Source"
            noAliases={true}
            stixDomainObject={dataSource}
            EditComponent={(
              <Security needs={[KNOWLEDGE_KNUPDATE]}>
                <DataSourceEdition dataSourceId={dataSource.id} />
              </Security>
            )}
            DeleteComponent={({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => (
              <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                <DataSourceDeletion id={dataSource.id} isOpen={isOpen} handleClose={onClose} />
              </Security>
            )}
            redirectToContent={true}
            enableEnrollPlaybook={true}
          />
          <StixDomainObjectMain
            basePath="/dashboard/techniques/data_sources"
            entity={dataSource}
            pages={{
              overview:
                <DataSource dataSourceData={dataSource} />,
              content: (
                <StixCoreObjectContentRoot
                  stixCoreObject={dataSource}
                />
              ),
              files: (
                <FileManager
                  id={dataSourceId}
                  connectorsImport={connectorsForImport}
                  connectorsExport={connectorsForExport}
                  entity={dataSource}
                />
              ),
              history:
                <StixCoreObjectHistory stixCoreObjectId={dataSourceId} />,
            }}
            extraRoutes={(
              <>
                <Route
                  path="/knowledge/*"
                  element={(
                    <DataSourceKnowledgeComponent
                      data={dataSource}
                      enableReferences={settings?.platform_enable_reference?.includes(
                        'Data-Source',
                      )}
                    />
                  )}
                />,
              </>
            )}
          />
        </div>
      ) : (
        <ErrorNotFound />
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
