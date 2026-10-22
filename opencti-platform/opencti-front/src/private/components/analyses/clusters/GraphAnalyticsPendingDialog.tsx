import React, { Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Link } from 'react-router';
import { Text } from '@filigran/design-system';
import { Box, Skeleton } from '@mui/material';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useGranted, { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import useEntityTranslation from '../../../../utils/hooks/useEntityTranslation';
import { resolveLink } from '../../../../utils/Entity';
import { MESSAGING$ } from '../../../../relay/environment';
import { reportPayloadErrors } from '../../common/graph_analytics/graphAnalyticsUtils';
import type { GraphAnalyticsPendingDialogQuery } from './__generated__/GraphAnalyticsPendingDialogQuery.graphql';
import type { GraphAnalyticsPendingDialogRecomputeMutation } from './__generated__/GraphAnalyticsPendingDialogRecomputeMutation.graphql';

const PENDING_SHOWN = 50;

const pendingQuery = graphql`
  query GraphAnalyticsPendingDialogQuery($first: Int) {
    graphAnalyticsPendingEntities(first: $first) {
      id
      entity_type
      representative {
        main
      }
    }
  }
`;

const recomputeMutation = graphql`
  mutation GraphAnalyticsPendingDialogRecomputeMutation($ids: [String!]!) {
    graphAnalyticsRequestRecompute(ids: $ids)
  }
`;

interface PendingListProps {
  queryRef: PreloadedQuery<GraphAnalyticsPendingDialogQuery>;
  pendingCount: number;
  onClose: () => void;
}

const PendingList = ({ queryRef, pendingCount, onClose }: PendingListProps) => {
  const { t_i18n } = useFormatter();
  const { translateEntityType } = useEntityTranslation();
  const canRecompute = useGranted([KNOWLEDGE_KNUPDATE]);
  const [commitRecompute, recomputing] = useApiMutation<GraphAnalyticsPendingDialogRecomputeMutation>(recomputeMutation);
  const { graphAnalyticsPendingEntities: entities } = usePreloadedQuery(pendingQuery, queryRef);
  if (entities.length === 0) {
    return <Text variant="content-base">{t_i18n('None of the entities waiting for analysis is accessible to you.')}</Text>;
  }
  const hidden = Math.max(0, pendingCount - entities.length);
  const analyseNow = () => commitRecompute({
    variables: { ids: entities.map((entity) => entity.id) },
    onCompleted: (_, errors) => {
      if (reportPayloadErrors(errors)) return;
      MESSAGING$.notifySuccess(t_i18n('These entities will be analysed in the next minutes'));
      onClose();
    },
  });
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
      <Text variant="content-compact">
        {t_i18n('Entities are analysed about a minute after their last change, in this order.')}
      </Text>
      <Box component="ul" sx={{ listStyle: 'none', m: 0, p: 0, display: 'flex', flexDirection: 'column', gap: 1 }} data-testid="graph-analytics-pending-list">
        {entities.map((entity) => (
          <Box component="li" key={entity.id} sx={{ display: 'flex', alignItems: 'center', gap: 1, minWidth: 0 }}>
            <ItemIcon type={entity.entity_type} size="small" />
            <Link to={`${resolveLink(entity.entity_type)}/${entity.id}`} onClick={onClose}>
              <Text variant="content-compact-medium" as="span">{entity.representative.main}</Text>
            </Link>
            <Text variant="content-caption" as="span">{translateEntityType(entity.entity_type)}</Text>
          </Box>
        ))}
      </Box>
      {hidden > 0 && (
        <Text variant="content-caption">
          {t_i18n('and {count, plural, one {# more entity} other {# more entities}}', { values: { count: hidden } })}
        </Text>
      )}
      {canRecompute && (
        <Box sx={{ display: 'flex', justifyContent: 'flex-end' }}>
          <Button onClick={analyseNow} disabled={recomputing} data-testid="graph-analytics-pending-analyse">
            {t_i18n('Analyse them now')}
          </Button>
        </Box>
      )}
    </Box>
  );
};

interface GraphAnalyticsPendingDialogProps {
  pendingCount: number;
  onClose: () => void;
}

/** What "Entities waiting for analysis" counts: the next queued entities the reader can access, and a way to rush them. */
const GraphAnalyticsPendingDialog = ({ pendingCount, onClose }: GraphAnalyticsPendingDialogProps) => {
  const { t_i18n } = useFormatter();
  const queryRef = useQueryLoading<GraphAnalyticsPendingDialogQuery>(pendingQuery, { first: PENDING_SHOWN });
  const skeleton = <Skeleton variant="rounded" height={160} />;
  return (
    <Dialog open onClose={onClose} title={t_i18n('Entities waiting for analysis')} showCloseButton>
      {queryRef ? (
        <Suspense fallback={skeleton}>
          <PendingList queryRef={queryRef} pendingCount={pendingCount} onClose={onClose} />
        </Suspense>
      ) : skeleton}
    </Dialog>
  );
};

export default GraphAnalyticsPendingDialog;
