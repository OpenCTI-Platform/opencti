import React, { Suspense, useMemo } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useSubscription } from 'react-relay';
import { useLocation, useParams } from 'react-router';
import { useTheme } from '@mui/styles';
import StixCoreObjectContentRoot from '@components/common/stix_core_objects/StixCoreObjectContentRoot';
import FileManager from '@components/common/files/FileManager';
import StixCoreObjectHistory from '@components/common/stix_core_objects/StixCoreObjectHistory';
import StixDomainObjectHeader from '@components/common/stix_domain_objects/StixDomainObjectHeader';
import StixDomainObjectMain from '@components/common/stix_domain_objects/StixDomainObjectMain';
import Loader, { LoaderVariant } from '../../../components/Loader';
import ErrorNotFound from '../../../components/ErrorNotFound';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import Security from '../../../utils/Security';
import { useGetCurrentUserAccessRight } from '../../../utils/authorizedMembers';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import useGranted, { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../utils/hooks/useGranted';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { getPaddingRight } from '../../../utils/utils';
import { PATH_HUNT, PATH_HUNTS } from '../common/routes/paths';
import Hunt from './Hunt';
import HuntCoverage from './HuntCoverage';
import HuntDeletion from './HuntDeletion';
import HuntEdition from './HuntEdition';
import HuntEvidence from './HuntEvidence';
import HuntLogic from './HuntLogic';
import { HuntPackExportButton } from './HuntPack';
import HuntRuns from './runs/HuntRuns';
import HuntStatusHeader from './HuntStatusHeader';
import { HUNT_ENTITY_TYPE } from './hunt-utils';
import { RootHuntQuery } from './__generated__/RootHuntQuery.graphql';
import { RootHuntSubscription } from './__generated__/RootHuntSubscription.graphql';

const subscription = graphql`
  subscription RootHuntSubscription($id: ID!) {
    hunt(id: $id) {
      id
      hunt_status
      last_run_at
      last_run_status
      last_hits_count
      next_run_at
      hunt_pir_armed
      hunt_pir_armed_at
      ...Hunt_hunt
      ...HuntLogic_hunt
      ...HuntStatusHeader_hunt
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const huntQuery = graphql`
  query RootHuntQuery($id: String!) {
    hunt(id: $id) {
      id
      draftVersion {
        draft_id
        draft_operation
      }
      standard_id
      entity_type
      name
      description
      hunt_status
      hunt_type
      hunt_source_kind
      time_window_hours
      hunt_max_results
      scopePlatforms {
        id
        name
      }
      objectMarking {
        id
      }
      currentUserAccessRight
      ...Hunt_hunt
      ...HuntLogic_hunt
      ...HuntStatusHeader_hunt
      ...HuntCoverage_hunt
      ...StixCoreObjectContent_stixCoreObject
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
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

interface RootHuntComponentProps {
  queryRef: PreloadedQuery<RootHuntQuery>;
  huntId: string;
}

const RootHuntComponent = ({ queryRef, huntId }: RootHuntComponentProps) => {
  const theme = useTheme<Theme>();
  const location = useLocation();
  const { t_i18n } = useFormatter();
  const { hunt, connectorsForImport, connectorsForExport } = usePreloadedQuery<RootHuntQuery>(huntQuery, queryRef);
  const subConfig = useMemo(() => ({ subscription, variables: { id: huntId } }), [huntId]);
  useSubscription<RootHuntSubscription>(subConfig);
  // Same rule as the edit and delete controls of the entity header, in a draft the access to the draft too; the
  // edition of the hunt only exists with the update capability, so its shortcuts need it as well
  const canUpdate = useGranted([KNOWLEDGE_KNUPDATE]);
  const draftContext = useDraftContext();
  const accessRight = useGetCurrentUserAccessRight(hunt?.currentUserAccessRight);
  const draftAccessRight = useGetCurrentUserAccessRight(draftContext?.currentUserAccessRight);
  const canEdit = canUpdate && accessRight.canEdit && (!draftContext || draftAccessRight.canEdit);

  if (!hunt) {
    return <ErrorNotFound />;
  }
  const basePath = PATH_HUNT(huntId);
  const paddingRight = getPaddingRight(location.pathname, basePath, false);
  const isContent = location.pathname.includes(`${basePath}/content`);

  return (
    <div style={{ paddingRight }} data-testid="hunt-details-page">
      <Breadcrumbs elements={[
        { label: t_i18n('Defense') },
        { label: t_i18n('Hunts'), link: PATH_HUNTS },
        { label: hunt.name, current: true },
      ]}
      />
      <StixDomainObjectHeader
        entityType={HUNT_ENTITY_TYPE}
        stixDomainObject={hunt}
        EditComponent={(
          <Security needs={[KNOWLEDGE_KNUPDATE]} hasAccess={canEdit}>
            <HuntEdition huntId={hunt.id} />
          </Security>
        )}
        DeleteComponent={({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => (
          <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
            <HuntDeletion huntId={hunt.id} isOpen={isOpen} handleClose={onClose} />
          </Security>
        )}
        enableQuickSubscription
        redirectToContent
        noAliases
      />
      {!isContent && <HuntStatusHeader data={hunt} canEdit={canEdit} />}
      <StixDomainObjectMain
        entity={hunt}
        basePath={basePath}
        pages={{
          overview: <Hunt data={hunt} canEdit={canEdit} />,
          logic: <HuntLogic data={hunt} canEdit={canEdit} />,
          runs: <HuntRuns hunt={hunt} canEdit={canEdit} />,
          evidence: <HuntEvidence huntId={hunt.id} />,
          coverage: <HuntCoverage data={hunt} />,
          content: <StixCoreObjectContentRoot stixCoreObject={hunt} />,
          files: (
            <FileManager
              id={huntId}
              connectorsImport={connectorsForImport}
              connectorsExport={connectorsForExport}
              entity={hunt}
            />
          ),
          history: <StixCoreObjectHistory stixCoreObjectId={huntId} />,
        }}
        extraActions={!isContent && (
          <div style={{ display: 'flex', gap: theme.spacing(1), alignItems: 'center' }}>
            <HuntPackExportButton ids={[hunt.id]} />
          </div>
        )}
      />
    </div>
  );
};

const Root = () => {
  const { huntId } = useParams() as { huntId: string };
  const queryRef = useQueryLoading<RootHuntQuery>(huntQuery, { id: huntId });
  return (
    <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
      {queryRef && <RootHuntComponent queryRef={queryRef} huntId={huntId} />}
    </Suspense>
  );
};

export default Root;
