import { Suspense, useMemo } from 'react';
import { useLocation, useParams } from 'react-router-dom';
import { graphql, PreloadedQuery, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import { RootIndicatorQuery } from '@components/observations/indicators/__generated__/RootIndicatorQuery.graphql';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import { RootIndicatorSubscription } from '@components/observations/indicators/__generated__/RootIndicatorSubscription.graphql';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import CreateRelationshipContextProvider from '@components/common/stix_core_relationships/CreateRelationshipContextProvider';
import StixCoreRelationshipCreationFromEntityHeader from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntityHeader';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import Indicator from './Indicator';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import FileManager from '../../common/files/FileManager';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixDomainObjectMain from '@components/common/stix_domain_objects/StixDomainObjectMain';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getPaddingRight } from '../../../../utils/utils';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import IndicatorEdition from './IndicatorEdition';
import IndicatorDeletion from './IndicatorDeletion';
import IndicatorKnowledge from './IndicatorKnowledge';
import { PATH_INDICATOR, PATH_INDICATORS } from '@components/common/routes/paths';

const subscription = graphql`
  subscription RootIndicatorSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Indicator {
        ...Indicator_indicator
        ...IndicatorEditionContainer_indicator
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const indicatorQuery = graphql`
  query RootIndicatorQuery($id: String!) {
    indicator(id: $id) {
      id
      draftVersion {
        draft_id
        draft_operation
      }
      standard_id
      entity_type
      name
      pattern
      currentUserAccessRight
      ...StixCoreRelationshipCreationFromEntityHeader_stixCoreObject
      ...Indicator_indicator
      ...IndicatorDetails_indicator
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

type RootIndicatorProps = {
  indicatorId: string;
  queryRef: PreloadedQuery<RootIndicatorQuery>;
};

const RootIndicator = ({ indicatorId, queryRef }: RootIndicatorProps) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootIndicatorSubscription>>(() => ({
    subscription,
    variables: { id: indicatorId },
  }), [indicatorId]);

  const location = useLocation();
  const { t_i18n } = useFormatter();
  useSubscription<RootIndicatorSubscription>(subConfig);

  const {
    indicator,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootIndicatorQuery>(indicatorQuery, queryRef);

  const { forceUpdate } = useForceUpdate();
  const basePath = PATH_INDICATOR(indicatorId);
  const link = `${basePath}/knowledge`;
  const paddingRight = getPaddingRight(location.pathname, basePath, false);
  return (
    <CreateRelationshipContextProvider>
      {indicator ? (
        <div style={{ paddingRight }}>
          <Breadcrumbs elements={[
            { label: t_i18n('Observations') },
            { label: t_i18n('Indicators'), link: PATH_INDICATORS },
            { label: (indicator.name ?? indicator.pattern ?? ''), current: true },
          ]}
          />
          <StixDomainObjectHeader
            entityType="Indicator"
            stixDomainObject={indicator}
            EditComponent={(
              <Security needs={[KNOWLEDGE_KNUPDATE]}>
                <IndicatorEdition indicatorId={indicator.id} />
              </Security>
            )}
            RelateComponent={(
              <Security needs={[KNOWLEDGE_KNUPDATE]}>
                <StixCoreRelationshipCreationFromEntityHeader
                  data={indicator}
                />
              </Security>
            )}
            DeleteComponent={({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => (
              <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                <IndicatorDeletion id={indicator.id} isOpen={isOpen} handleClose={onClose} />
              </Security>
            )}
            noAliases={true}
            enableEnricher={true}
            enableEnrollPlaybook={true}
            redirectToContent={true}
          />
          <StixDomainObjectMain
            entityType="Indicator"
            basePath={basePath}
            pages={{
              overview: <Indicator indicatorData={indicator} />,
              knowledge: (
                <div key={forceUpdate}>
                  <IndicatorKnowledge
                    indicatorId={indicatorId}
                  />
                </div>
              ),
              content: (
                <StixCoreObjectContentRoot
                  stixCoreObject={indicator}
                />
              ),
              analyses: (
                <StixCoreObjectOrStixCoreRelationshipContainers
                  stixDomainObjectOrStixCoreRelationship={indicator}
                />
              ),
              sightings: (
                <EntityStixSightingRelationships
                  entityId={indicatorId}
                  entityLink={link}
                  noPadding={true}
                  isTo={false}
                  stixCoreObjectTypes={[
                    'Region',
                    'Country',
                    'City',
                    'Sector',
                    'Organization',
                    'Individual',
                    'System',
                  ]}
                />
              ),
              files: (
                <FileManager
                  id={indicatorId}
                  connectorsImport={connectorsForImport}
                  connectorsExport={connectorsForExport}
                  entity={indicator}
                />
              ),
              history: (
                <StixCoreObjectHistory
                  stixCoreObjectId={indicatorId}
                />
              ),
            }}
          />
        </div>
      ) : (
        <ErrorNotFound />
      )}
    </CreateRelationshipContextProvider>
  );
};

const Root = () => {
  const { indicatorId } = useParams() as { indicatorId: string };
  const queryRef = useQueryLoading<RootIndicatorQuery>(indicatorQuery, {
    id: indicatorId,
  });

  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootIndicator indicatorId={indicatorId} queryRef={queryRef} />
        </Suspense>
      )}
    </>
  );
};

export default Root;
