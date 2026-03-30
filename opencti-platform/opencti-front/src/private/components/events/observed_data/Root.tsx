import { Suspense, useMemo } from 'react';
import { Route, Routes, useParams } from 'react-router-dom';
import { graphql, PreloadedQuery, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import { RootObservedDataSubscription } from './__generated__/RootObservedDataSubscription.graphql';
import { RootObservedDataQuery } from './__generated__/RootObservedDataQuery.graphql';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import ObservedData from './ObservedData';
import FileManager from '../../common/files/FileManager';
import StixDomainObjectTabsBox from '@components/common/stix_domain_objects/StixDomainObjectTabsBox';
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
import useEntityTranslation from '../../../../utils/hooks/useEntityTranslation';

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
  const { translateEntityType } = useEntityTranslation();

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
          { label: translateEntityType('Observed-Data', { plural: true }), link: '/dashboard/events/observed_data' },
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
          DeleteComponent={({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => (
            <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
              <ObservedDataDeletion id={observedData.id} isOpen={isOpen} handleClose={onClose} />
            </Security>
          )}
          redirectToContent={false}
          disableAuthorizedMembers={true}
          enableEnricher={false}
        />
        <StixDomainObjectTabsBox
          basePath="/dashboard/events/observed_data"
          entity={observedData}
          tabs={[
            'overview',
            'entities',
            'observables',
            'files',
            'history',
          ]}
        />
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
            element={(
              <FileManager
                id={observedDataId}
                connectorsExport={connectorsForExport}
                connectorsImport={connectorsForImport}
                entity={observedData}
              />
            )}
          />
          <Route
            path="/history"
            element={
              <StixCoreObjectHistory stixCoreObjectId={observedDataId} />
            }
          />
          <Route
            path="/knowledge/relations/:relationId/"
            element={(
              <StixCoreRelationship
                entityId={observedData.id}
              />
            )}
          />
        </Routes>
      </div>
    </>
  );
};

const Root = () => {
  const { observedDataId } = useParams() as { observedDataId: string };
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
