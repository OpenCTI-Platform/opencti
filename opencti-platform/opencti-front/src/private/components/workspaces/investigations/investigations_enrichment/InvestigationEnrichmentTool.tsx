import { startTransition, Suspense, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { CloudRefreshOutline } from 'mdi-material-ui';
import GraphToolbarItem from '../../../../../components/graph/components/GraphToolbarItem';
import { useFormatter } from '../../../../../components/i18n';
import { GraphEntity } from '../../../../../components/graph/graph.types';
import { useGetCurrentUserAccessRight } from '../../../../../utils/authorizedMembers';
import { useGraphContext } from '../../../../../components/graph/GraphContext';
import useGranted, { INVESTIGATION_INUPDATE } from '../../../../../utils/hooks/useGranted';
import InvestigationEnrichmentDrawer from './InvestigationEnrichmentDrawer';
import { useQueryLoadingWithLoadQuery } from '../../../../../utils/hooks/useQueryLoading';
import { InvestigationEnrichmentToolQuery } from './__generated__/InvestigationEnrichmentToolQuery.graphql';
import useIntervalBoostable from '../../../../../utils/hooks/useIntervalBoostable';

const investigationQuery = graphql`
  query InvestigationEnrichmentToolQuery($id: String!) {
    workspace(id: $id) {
      id
      currentUserAccessRight
      enrichmentWorks {
        edges {
          node {
            id
            status
            event_source_id
          }
        }
      }
    }
  }
`;

interface InvestigationEnrichmentToolComponentProps {
  queryRef: PreloadedQuery<InvestigationEnrichmentToolQuery>;
  onRefresh: () => void;
}

const InvestigationEnrichmentToolComponent = ({
  queryRef,
  onRefresh,
}: InvestigationEnrichmentToolComponentProps) => {
  const { t_i18n } = useFormatter();
  const [openEnrichment, setOpenEnrichment] = useState(false);
  const { workspace: investigation } = usePreloadedQuery(investigationQuery, queryRef);

  const canUpdate = useGranted([INVESTIGATION_INUPDATE]);
  const { canEdit } = useGetCurrentUserAccessRight(investigation?.currentUserAccessRight);

  const { graphState } = useGraphContext();
  const { selectedNodes, selectedLinks } = graphState;
  const selection = [...selectedNodes, ...selectedLinks];
  const hasSelection = selection.length > 0;

  if (!investigation) {
    return null;
  }

  return (
    <>
      <GraphToolbarItem
        color="primary"
        title={t_i18n('Enrichment')}
        Icon={<CloudRefreshOutline />}
        disabled={!canEdit || !canUpdate || !hasSelection}
        onClick={() => {
          setOpenEnrichment(true);
        }}
      />

      <InvestigationEnrichmentDrawer
        open={openEnrichment}
        investigation={investigation}
        onClose={() => setOpenEnrichment(false)}
        onLaunchCompleted={onRefresh}
      />
    </>
  );
};

interface InvestigationEnrichmentToolProps {
  entity: GraphEntity;
}

const InvestigationEnrichmentTool = ({
  entity,
}: InvestigationEnrichmentToolProps) => {
  const { t_i18n } = useFormatter();

  const [queryRef, loadQuery] = useQueryLoadingWithLoadQuery<InvestigationEnrichmentToolQuery>(
    investigationQuery,
    { id: entity.id },
  );

  const { activateBoost } = useIntervalBoostable(() => {
    startTransition(() => {
      loadQuery({ id: entity.id }, { fetchPolicy: 'network-only' });
    });
  }, {
    baseFrequency: 15000,
    boostFrequency: 3000,
    boostDuration: 10000,
  });

  const fallback = (
    <GraphToolbarItem
      disabled
      color="primary"
      title={t_i18n('Enrichment')}
      Icon={<CloudRefreshOutline />}
    />
  );

  return (
    <Suspense fallback={fallback}>
      {queryRef && (
        <InvestigationEnrichmentToolComponent
          queryRef={queryRef}
          onRefresh={activateBoost}
        />
      )}
    </Suspense>
  );
};

export default InvestigationEnrichmentTool;
