import { Suspense, useMemo } from 'react';
import { Route, Routes, useLocation, useParams } from 'react-router-dom';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import { graphql, PreloadedQuery, usePreloadedQuery, useSubscription } from 'react-relay';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import StixCyberObservable from '../stix_cyber_observables/StixCyberObservable';
import StixCyberObservableKnowledge from '../stix_cyber_observables/StixCyberObservableKnowledge';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCyberObservableHeader from '../stix_cyber_observables/StixCyberObservableHeader';
import StixDomainObjectTabsBox from '@components/common/stix_domain_objects/StixDomainObjectTabsBox';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import FileManager from '../../common/files/FileManager';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getPaddingRight } from '../../../../utils/utils';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import StixCyberObservableDeletion from '../stix_cyber_observables/StixCyberObservableDeletion';
import { useFormatter } from '../../../../components/i18n';
import { RootArtifactSubscription } from './__generated__/RootArtifactSubscription.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { RootArtifactQuery } from './__generated__/RootArtifactQuery.graphql';
import { useEntityTypeDisplayName } from '../../../../utils/hooks/useEntityTypeDisplayName';

const subscription = graphql`
  subscription RootArtifactSubscription($id: ID!) {
    stixCyberObservable(id: $id) {
      ...StixCyberObservable_stixCyberObservable
      ...StixCyberObservableEditionContainer_stixCyberObservable
      ...StixCyberObservableKnowledge_stixCyberObservable
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const rootArtifactQuery = graphql`
  query RootArtifactQuery($id: String!) {
    stixCyberObservable(id: $id) {
      id
      draftVersion {
        draft_id
        draft_operation
      }
      standard_id
      entity_type
      observable_value
      ...StixCyberObservable_stixCyberObservable
      ...StixCyberObservableHeader_stixCyberObservable
      ...StixCyberObservableDetails_stixCyberObservable
      ...StixCyberObservableIndicators_stixCyberObservable
      ...StixCyberObservableKnowledge_stixCyberObservable
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

interface RootArtifactProps {
  queryRef: PreloadedQuery<RootArtifactQuery>;
  observableId: string;
}

const RootArtifact = ({ queryRef, observableId }: RootArtifactProps) => {
  const location = useLocation();
  const { t_i18n } = useFormatter();
  const entityTypeDisplayName = useEntityTypeDisplayName();

  const subConfig = useMemo<GraphQLSubscriptionConfig<RootArtifactSubscription>>(
    () => ({
      subscription,
      variables: { id: observableId },
    }),
    [observableId],
  );
  useSubscription(subConfig);

  const {
    stixCyberObservable,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootArtifactQuery>(rootArtifactQuery, queryRef);
  if (!stixCyberObservable) {
    return <ErrorNotFound />;
  }

  const link = `/dashboard/observations/artifacts/${observableId}/knowledge`;
  const paddingRight = getPaddingRight(location.pathname, stixCyberObservable.id, '/dashboard/observations/artifacts', false);
  return (
    <div style={{ paddingRight }}>
      <Breadcrumbs elements={[
        { label: t_i18n('Observations') },
        { label: entityTypeDisplayName('Artifact', t_i18n('Artifacts')), link: '/dashboard/observations/artifacts' },
        { label: stixCyberObservable.observable_value, current: true },
      ]}
      />
      <StixCyberObservableHeader
        stixCyberObservable={stixCyberObservable}
        enableEnrollPlaybook={true}
        DeleteComponent={({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => (
          <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
            <StixCyberObservableDeletion id={stixCyberObservable.id} isOpen={isOpen} handleClose={onClose} />
          </Security>
        )}
      />
      <StixDomainObjectTabsBox
        basePath="/dashboard/observations/artifacts"
        entity={stixCyberObservable}
        tabs={[
          'overview',
          'knowledge',
          'content',
          'analyses',
          'sightings',
          'files',
          'history',
        ]}
      />
      <Routes>
        <Route
          path="/"
          element={(
            <StixCyberObservable
              stixCyberObservableData={stixCyberObservable}
            />
          )}
        />
        <Route
          path="/knowledge"
          element={(
            <StixCyberObservableKnowledge
              stixCyberObservable={stixCyberObservable}
              connectorsForImport={connectorsForImport}
            />
          )}
        />
        <Route
          path="/content/*"
          element={(
            <StixCoreObjectContentRoot
              stixCoreObject={stixCyberObservable}
            />
          )}
        />
        <Route
          path="/sightings"
          element={(
            <EntityStixSightingRelationships
              isTo={false}
              entityId={observableId}
              entityLink={link}
              noPadding={true}
              stixCoreObjectTypes={[
                'Region',
                'Country',
                'City',
                'Position',
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
              id={observableId}
              connectorsImport={connectorsForImport}
              connectorsExport={connectorsForExport}
              entity={stixCyberObservable}
              isArtifact={true}
              directDownload={true}
            />
          )}
        />
        <Route
          path="/history"
          element={(
            <StixCoreObjectHistory
              stixCoreObjectId={observableId}
            />
          )}
        />
        <Route
          path="/knowledge/relations/:relationId"
          element={(
            <StixCoreRelationship
              entityId={observableId}
            />
          )}
        />
        <Route
          path="/knowledge/sightings/:sightingId"
          element={(
            <StixSightingRelationship
              entityId={observableId}
              paddingRight
            />
          )}
        />
      </Routes>
    </div>
  );
};

const Root = () => {
  const { observableId } = useParams() as { observableId: string };
  const queryRef = useQueryLoading<RootArtifactQuery>(rootArtifactQuery, {
    id: observableId,
  });
  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootArtifact queryRef={queryRef} observableId={observableId} />
        </Suspense>
      )}
    </>
  );
};

export default Root;
