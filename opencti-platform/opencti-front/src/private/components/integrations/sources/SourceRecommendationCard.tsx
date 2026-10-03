import React, { useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Link } from 'react-router';
import { Box, Collapse, Stack, Typography } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { Textarea } from '@filigran/design-system';
import { CheckOutlined, CloseOutlined, ExpandLessOutlined, ExpandMoreOutlined, UndoOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import Card from '@common/card/Card';
import Dialog from '@common/dialog/Dialog';
import FormButtonContainer from '@common/form/FormButtonContainer';
import Tag from '@common/tag/Tag';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useGranted, { INGESTION_SETINGESTIONS, MODULES_MODMANAGE } from '../../../../utils/hooks/useGranted';
import type { Theme } from '../../../../components/Theme';
import { parseJsonObject, RECOMMENDATION_KIND_LABELS, RECOMMENDATION_STATUS_LABELS } from './sourceIntelligenceUtils';
import { SourceRecommendationCard_recommendation$key } from './__generated__/SourceRecommendationCard_recommendation.graphql';
import { SourceRecommendationCardApplyMutation } from './__generated__/SourceRecommendationCardApplyMutation.graphql';
import { SourceRecommendationCardRevertMutation } from './__generated__/SourceRecommendationCardRevertMutation.graphql';
import { SourceRecommendationCardDismissMutation } from './__generated__/SourceRecommendationCardDismissMutation.graphql';
import notifyMutationOutcome from './notifyMutationOutcome';

const recommendationFragment = graphql`
  fragment SourceRecommendationCard_recommendation on SourceRecommendation {
    id
    name
    kind
    status
    rationale
    payload
    evidence
    apply_result
    error_message
    autonomous
    pir_id
    collection_gap_id
    proposed_at
    applied_at
    reverted_at
    dismissed_at
    dismiss_reason
    source {
      id
      name
      source_kind
    }
    applied_by {
      id
      name
    }
    reverted_by {
      id
      name
    }
    dismissed_by {
      id
      name
    }
  }
`;

const applyMutation = graphql`
  mutation SourceRecommendationCardApplyMutation($id: ID!, $input: SourceRecommendationApplyInput) {
    applySourceRecommendation(id: $id, input: $input) {
      status
      error_message
      ...SourceRecommendationCard_recommendation
    }
  }
`;

const revertMutation = graphql`
  mutation SourceRecommendationCardRevertMutation($id: ID!) {
    revertSourceRecommendation(id: $id) {
      ...SourceRecommendationCard_recommendation
    }
  }
`;

const dismissMutation = graphql`
  mutation SourceRecommendationCardDismissMutation($id: ID!, $reason: String) {
    dismissSourceRecommendation(id: $id, reason: $reason) {
      ...SourceRecommendationCard_recommendation
    }
  }
`;

// Payload keys rendered as a before / after change
const CHANGE_PAIRS: Array<[string, string, string]> = [
  ['current_max_confidence', 'proposed_max_confidence', 'Max confidence level'],
  ['current_value', 'proposed_value', 'Schedule'],
];
const HIDDEN_PAYLOAD_KEYS = new Set(['user_id', 'group_id', 'connector_id', 'feed_id', 'peer_source_id', 'collection_gap_id', 'pir_id', 'contract_image', 'catalog_id']);

interface SourceRecommendationCardProps {
  data: SourceRecommendationCard_recommendation$key;
  hideSource?: boolean;
  onChange?: () => void;
}

const SourceRecommendationCard = ({ data, hideSource = false, onChange }: SourceRecommendationCardProps) => {
  const { t_i18n, nsdt } = useFormatter();
  const theme = useTheme<Theme>();
  const recommendation = useFragment(recommendationFragment, data);
  const canManage = useGranted([MODULES_MODMANAGE, INGESTION_SETINGESTIONS]);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [dismissOpen, setDismissOpen] = useState(false);
  const [dismissReason, setDismissReason] = useState('');
  const [commitApply, applying] = useApiMutation<SourceRecommendationCardApplyMutation>(applyMutation);
  const [commitRevert, reverting] = useApiMutation<SourceRecommendationCardRevertMutation>(revertMutation);
  const [commitDismiss, dismissing] = useApiMutation<SourceRecommendationCardDismissMutation>(dismissMutation);

  const payload = parseJsonObject(recommendation.payload);
  const statusColors: Record<string, string | undefined> = {
    proposed: theme.palette.primary.main,
    applied: theme.palette.success.main,
    dismissed: theme.palette.text.disabled,
    reverted: theme.palette.warn.main,
    failed: theme.palette.error.main,
  };
  const busy = applying || reverting || dismissing;
  const catalogSlug = recommendation.kind === 'add_connector' && typeof payload.slug === 'string' ? payload.slug : null;

  const handleApply = () => commitApply({
    variables: { id: recommendation.id, input: {} },
    onCompleted: (response, errors) => {
      const applied = response.applySourceRecommendation;
      const failure = !errors?.length && applied?.status !== 'applied'
        ? `${t_i18n('The recommendation could not be applied')}${applied?.error_message ? `: ${applied.error_message}` : ''}`
        : null;
      notifyMutationOutcome(errors, { success: t_i18n('Recommendation applied'), failure });
      onChange?.();
    },
  });
  const handleRevert = () => commitRevert({
    variables: { id: recommendation.id },
    onCompleted: (_, errors) => {
      if (notifyMutationOutcome(errors, { success: t_i18n('Recommendation reverted') })) onChange?.();
    },
  });
  const handleDismiss = () => commitDismiss({
    variables: { id: recommendation.id, reason: dismissReason.trim() || null },
    onCompleted: (_, errors) => {
      if (!notifyMutationOutcome(errors, { success: t_i18n('Recommendation dismissed') })) return;
      setDismissOpen(false);
      setDismissReason('');
      onChange?.();
    },
  });

  const changes = CHANGE_PAIRS
    .filter(([, after]) => payload[after] !== undefined && payload[after] !== null)
    .map(([before, after, label]) => ({ label, before: payload[before] ?? '-', after: payload[after] }));
  const details = Object.entries(payload).filter(([key, value]) => !HIDDEN_PAYLOAD_KEYS.has(key) && value !== null && typeof value !== 'object');

  let history: string | null = null;
  if (recommendation.status === 'applied' && recommendation.applied_at) {
    history = `${t_i18n('Applied')} ${nsdt(recommendation.applied_at)}${recommendation.autonomous ? ` (${t_i18n('autonomous')})` : ''}${recommendation.applied_by ? ` - ${recommendation.applied_by.name}` : ''}`;
  } else if (recommendation.status === 'reverted' && recommendation.reverted_at) {
    history = `${t_i18n('Reverted')} ${nsdt(recommendation.reverted_at)}${recommendation.reverted_by ? ` - ${recommendation.reverted_by.name}` : ''}`;
  } else if (recommendation.status === 'dismissed' && recommendation.dismissed_at) {
    history = `${t_i18n('Dismissed')} ${nsdt(recommendation.dismissed_at)}${recommendation.dismissed_by ? ` - ${recommendation.dismissed_by.name}` : ''}${recommendation.dismiss_reason ? `: ${recommendation.dismiss_reason}` : ''}`;
  }

  return (
    <Card padding="small" data-testid={`source-recommendation-${recommendation.id}`}>
      <Stack direction="row" justifyContent="space-between" alignItems="flex-start" gap={2}>
        <Box sx={{ minWidth: 0, flex: 1 }}>
          <Stack direction="row" gap={1} alignItems="center" flexWrap="wrap" sx={{ marginBottom: 1 }}>
            <Tag label={t_i18n(RECOMMENDATION_KIND_LABELS[recommendation.kind] ?? recommendation.kind)} />
            <Tag label={t_i18n(RECOMMENDATION_STATUS_LABELS[recommendation.status] ?? recommendation.status)} color={statusColors[recommendation.status]} />
            {!hideSource && recommendation.source && (
              <Link to={`/dashboard/integrations/sources/source/${recommendation.source.id}`}>
                {recommendation.source.name}
              </Link>
            )}
            <Typography variant="caption" sx={{ color: theme.palette.text.secondary }}>
              {`${t_i18n('Proposed')} ${nsdt(recommendation.proposed_at)}`}
            </Typography>
          </Stack>
          <Typography variant="body2">{recommendation.rationale}</Typography>
          {changes.map((change) => (
            <Typography key={change.label} variant="body2" sx={{ marginTop: 0.5, color: theme.palette.text.secondary }}>
              {`${t_i18n(change.label)}: ${String(change.before)} -> ${String(change.after)}`}
            </Typography>
          ))}
          {history && (
            <Typography variant="caption" component="div" sx={{ marginTop: 1, color: theme.palette.text.secondary }}>{history}</Typography>
          )}
          {recommendation.apply_result && recommendation.status === 'applied' && (
            <Typography variant="caption" component="div" sx={{ color: theme.palette.success.main }}>{recommendation.apply_result}</Typography>
          )}
          {recommendation.error_message && (
            <Typography variant="caption" component="div" sx={{ color: theme.palette.error.main }}>{recommendation.error_message}</Typography>
          )}
          {details.length > 0 && (
            <>
              <Box sx={{ marginTop: 0.5 }}>
                <Button
                  variant="tertiary"
                  size="small"
                  onClick={() => setDetailsOpen(!detailsOpen)}
                  startIcon={detailsOpen ? <ExpandLessOutlined /> : <ExpandMoreOutlined />}
                  aria-expanded={detailsOpen}
                >
                  {t_i18n('Details')}
                </Button>
              </Box>
              <Collapse in={detailsOpen}>
                <Box component="dl" sx={{ margin: 0, display: 'grid', gridTemplateColumns: 'max-content 1fr', columnGap: 2, rowGap: 0.5 }}>
                  {details.map(([key, value]) => (
                    <React.Fragment key={key}>
                      <Typography component="dt" variant="caption" sx={{ color: theme.palette.text.secondary }}>{key}</Typography>
                      <Typography component="dd" variant="caption" sx={{ margin: 0, wordBreak: 'break-word' }}>{String(value)}</Typography>
                    </React.Fragment>
                  ))}
                </Box>
              </Collapse>
            </>
          )}
        </Box>
        {canManage && (
          <Stack direction="row" gap={1} flexShrink={0}>
            {catalogSlug && recommendation.status === 'proposed' && (
              <Button
                variant="secondary"
                size="small"
                component={Link}
                to={`/dashboard/integrations/catalog/${catalogSlug}`}
              >
                {t_i18n('Open in catalog')}
              </Button>
            )}
            {(recommendation.status === 'proposed' || recommendation.status === 'failed') && (
              <Button size="small" startIcon={<CheckOutlined />} onClick={handleApply} disabled={busy} data-testid="source-recommendation-apply">
                {catalogSlug ? t_i18n('Deploy') : t_i18n('Apply')}
              </Button>
            )}
            {recommendation.status === 'proposed' && (
              <Button variant="secondary" size="small" startIcon={<CloseOutlined />} onClick={() => setDismissOpen(true)} disabled={busy} data-testid="source-recommendation-dismiss">
                {t_i18n('Dismiss')}
              </Button>
            )}
            {recommendation.status === 'applied' && (
              <Button variant="secondary" size="small" startIcon={<UndoOutlined />} onClick={handleRevert} disabled={busy} data-testid="source-recommendation-revert">
                {t_i18n('Revert')}
              </Button>
            )}
          </Stack>
        )}
      </Stack>
      <Dialog open={dismissOpen} onClose={() => setDismissOpen(false)} title={t_i18n('Dismiss the recommendation')} size="small">
        <Typography variant="body2" sx={{ marginBottom: 2 }}>
          {t_i18n('A dismissed recommendation is not proposed again during the cooldown period configured in the settings.')}
        </Typography>
        <Textarea
          label={t_i18n('Reason')}
          value={dismissReason}
          onChange={(event) => setDismissReason(event.target.value)}
          maxLength={500}
        />
        <FormButtonContainer>
          <Button variant="secondary" onClick={() => setDismissOpen(false)} disabled={dismissing}>{t_i18n('Cancel')}</Button>
          <Button onClick={handleDismiss} disabled={dismissing}>{t_i18n('Dismiss')}</Button>
        </FormButtonContainer>
      </Dialog>
    </Card>
  );
};

export default SourceRecommendationCard;
