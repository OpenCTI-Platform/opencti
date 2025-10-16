import React, { Suspense, useMemo } from 'react';
import { Link, Route, Routes, useLocation, useParams } from 'react-router-dom';
import { graphql, PreloadedQuery, usePreloadedQuery, useSubscription } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import { RootObservedDataSubscription } from './__generated__/RootObservedDataSubscription.graphql';
import { RootObservedDataQuery } from './__generated__/RootObservedDataQuery.graphql';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import ObservedData from './ObservedData';
import FileManager from '../../common/files/FileManager';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import ContainerHeader from '../../common/containers/ContainerHeader';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import ContainerStixDomainObjects from '../../common/containers/ContainerStixDomainObjects';
import ContainerStixCyberObservables from '../../common/containers/ContainerStixCyberObservables';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import ObservedDataEdition from './ObservedDataEdition';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import ObservedDataDeletion from './ObservedDataDeletion';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';

const subscription = graphql`
  subscription RootObservedDataSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on ObservedData {
        ...ObservedData_observedData
        ...ObservedDataEditionContainer_observedData
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const observedDataQuery = graphql`
  query RootObservedDataQuery($id: String!) {
    observedData(id: $id) {
      id
      standard_id
      entity_type
      name
      ...ObservedData_observedData
      ...ObservedDataDetails_observedData
      ...ContainerHeader_container
      ...ContainerStixDomainObjects_container
      ...ContainerStixCyberObservables_container
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
    connectorsForImport {
      ...FileManager_connectorsImport
    }
  }
`;

type RootObservedDataProps = {
  observedDataId: string;
  queryRef: PreloadedQuery<RootObservedDataQuery>;
};

const RootObservedData = ({ queryRef, observedDataId }: RootObservedDataProps) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootObservedDataSubscription>>(() => ({
    subscription,
    variables: { id: observedDataId },
  }), [observedDataId]);

  const { t_i18n } = useFormatter();
  const location = useLocation();

  useSubscription<RootObservedDataSubscription>(subConfig);

  const {
    observedData,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootObservedDataQuery>(observedDataQuery, queryRef);

  if (!observedData) {
    return <ErrorNotFound />;
  }

  return (
    <>
      <div>
        <Breadcrumbs elements={[
          { label: t_i18n('Events') },
          { label: t_i18n('Observed datas'), link: '/dashboard/events/observed_data' },
          { label: observedData.name, current: true },
        ]}
        />
        <ContainerHeader
          container={observedData}
          EditComponent={(
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <ObservedDataEdition observedDataId={observedData.id} />
            </Security>
                    )}
          DeleteComponent={({ isOpen, onClose }: { isOpen: boolean, onClose: () => void }) => (
            <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
              <ObservedDataDeletion id={observedData.id} isOpen={isOpen} handleClose={onClose} />
            </Security>
          )}
          redirectToContent = {false}
          disableAuthorizedMembers={true}
          enableEnricher={false}
        />
        <Box
          sx={{
            borderBottom: 1,
            borderColor: 'divider',
            marginBottom: 3,
          }}
        >
          <Tabs
            value={location.pathname}
          >
            <Tab
              component={Link}
              to={`/dashboard/events/observed_data/${observedData.id}`}
              value={`/dashboard/events/observed_data/${observedData.id}`}
              label={t_i18n('Overview')}
            />
            <Tab
              component={Link}
              to={`/dashboard/events/observed_data/${observedData.id}/entities`}
              value={`/dashboard/events/observed_data/${observedData.id}/entities`}
              label={t_i18n('Entities')}
            />
            <Tab
              component={Link}
              to={`/dashboard/events/observed_data/${observedData.id}/observables`}
              value={`/dashboard/events/observed_data/${observedData.id}/observables`}
              label={t_i18n('Observables')}
            />
            <Tab
              component={Link}
              to={`/dashboard/events/observed_data/${observedData.id}/files`}
              value={`/dashboard/events/observed_data/${observedData.id}/files`}
              label={t_i18n('Data')}
            />
            <Tab
              component={Link}
              to={`/dashboard/events/observed_data/${observedData.id}/history`}
              value={`/dashboard/events/observed_data/${observedData.id}/history`}
              label={t_i18n('History')}
            />
          </Tabs>
        </Box>
        <Routes>
          <Route
            path="/"
            element={
              <ObservedData observedDataData={observedData} />
                      }
          />
          <Route
            path="/entities"
            element={
              <ContainerStixDomainObjects container={observedData} />
                      }
          />
          <Route
            path="/observables"
            element={
              <ContainerStixCyberObservables container={observedData} />
                      }
          />
          <Route
            path="/files"
            element={
              <FileManager
                id={observedDataId}
                connectorsExport={connectorsForExport}
                connectorsImport={connectorsForImport}
                entity={observedData}
              />
                      }
          />
          <Route
            path="/history"
            element={
              <StixCoreObjectHistory stixCoreObjectId={observedDataId} />
                      }
          />
          <Route
            path="/knowledge/relations/:relationId/"
            element={
              <StixCoreRelationship
                entityId={observedData.id}
              />
                      }
          />
        </Routes>
      </div>
    </>
  );
};

const Root = () => {
  const { observedDataId } = useParams() as { observedDataId: string; };
  const queryRef = useQueryLoading<RootObservedDataQuery>(observedDataQuery, {
    id: observedDataId,
  });

  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootObservedData queryRef={queryRef} observedDataId={observedDataId} />
        </Suspense>
      )}
    </>
  );
};

export default Root;
