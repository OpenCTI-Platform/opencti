import React, { useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Link } from 'react-router';
import { Box, Collapse, Stack, Typography } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { Alert, Chip, type ChipSeverity, Textarea, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { CheckOutlined, CloseOutlined, ExpandLessOutlined, ExpandMoreOutlined, UndoOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import Card from '@common/card/Card';
import Dialog from '@common/dialog/Dialog';
import FormButtonContainer from '@common/form/FormButtonContainer';
import { useFormatter } from '../../../../components/i18n';
import { useSourceMetricFormat } from './SourceMetricValue';
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
// Payload details worth showing, with their label; identifiers and technical keys stay hidden
const PAYLOAD_LABELS: Record<string, string> = {
  decay_lifetime: 'Decay lifetime (days)',
  decay_pound: 'Decay factor',
  decay_revoke_score: 'Revoke score',
  max_values: 'Maximum values',
  overlap_share: 'Overlap with the other source',
  title: 'Integration',
  origin: 'Recommended from',
};
const PAYLOAD_VALUE_LABELS: Record<string, Record<string, string>> = {
  origin: { hub: 'XTM Hub', local: 'Local catalog' },
};

const STATUS_SEVERITIES: Record<string, ChipSeverity> = {
  proposed: 'info',
  applied: 'low',
  failed: 'high',
  dismissed: 'neutral',
  reverted: 'neutral',
};

interface SourceRecommendationCardProps {
  data: SourceRecommendationCard_recommendation$key;
  hideSource?: boolean;
  onChange?: () => void;
}

const SourceRecommendationCard = ({ data, hideSource = false, onChange }: SourceRecommendationCardProps) => {
  const { t_i18n, rd, fldt } = useFormatter();
  const theme = useTheme<Theme>();
  const format = useSourceMetricFormat();
  const recommendation = useFragment(recommendationFragment, data);
  const canManage = useGranted([MODULES_MODMANAGE, INGESTION_SETINGESTIONS]);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [dismissOpen, setDismissOpen] = useState(false);
  const [revertOpen, setRevertOpen] = useState(false);
  const [dismissReason, setDismissReason] = useState('');
  const [commitApply, applying] = useApiMutation<SourceRecommendationCardApplyMutation>(applyMutation);
  const [commitRevert, reverting] = useApiMutation<SourceRecommendationCardRevertMutation>(revertMutation);
  const [commitDismiss, dismissing] = useApiMutation<SourceRecommendationCardDismissMutation>(dismissMutation);

  const payload = parseJsonObject(recommendation.payload);
  const busy = applying || reverting || dismissing;
  const catalogSlug = recommendation.kind === 'add_connector' && typeof payload.slug === 'string' ? payload.slug : null;

  const handleApply = () => commitApply({
    variables: { id: recommendation.id, input: {} },
    onCompleted: (response, errors) => {
      const applied = response.applySourceRecommendation;
      let failure: string | null = null;
      if (!errors?.length && applied?.status !== 'applied') {
        failure = applied?.error_message
          ? t_i18n('The recommendation could not be applied: {reason}', { values: { reason: applied.error_message } })
          : t_i18n('The recommendation could not be applied.');
      }
      notifyMutationOutcome(errors, { success: t_i18n('Recommendation applied'), failure });
      onChange?.();
    },
  });
  const handleRevert = () => commitRevert({
    variables: { id: recommendation.id },
    onCompleted: (_, errors) => {
      setRevertOpen(false);
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
    .map(([before, after, label]) => t_i18n('{label}: {before} -> {after}', {
      values: { label: t_i18n(label), before: payload[before] === undefined || payload[before] === null ? t_i18n('Not set') : String(payload[before]), after: String(payload[after]) },
    }));
  const formatDetail = (key: string, value: unknown) => {
    if (key === 'overlap_share' && typeof value === 'number') return format.ratio(value, 0) ?? String(value);
    const valueLabel = PAYLOAD_VALUE_LABELS[key]?.[String(value)];
    return valueLabel ? t_i18n(valueLabel) : String(value);
  };
  const details = Object.entries(payload)
    .filter(([key, value]) => PAYLOAD_LABELS[key] && value !== null && typeof value !== 'object')
    .map(([key, value]) => ({ key, label: t_i18n(PAYLOAD_LABELS[key]), value: formatDetail(key, value) }));

  let history: { sentence: string; date: string } | null = null;
  if (recommendation.status === 'applied' && recommendation.applied_at) {
    const time = rd(recommendation.applied_at);
    let sentence = t_i18n('Applied {time}', { values: { time } });
    if (recommendation.autonomous) sentence = t_i18n('Applied automatically by the autonomy policy {time}', { values: { time } });
    else if (recommendation.applied_by) sentence = t_i18n('Applied by {user} {time}', { values: { user: recommendation.applied_by.name, time } });
    history = { sentence, date: recommendation.applied_at };
  } else if (recommendation.status === 'reverted' && recommendation.reverted_at) {
    const time = rd(recommendation.reverted_at);
    history = {
      sentence: recommendation.reverted_by
        ? t_i18n('Reverted by {user} {time}', { values: { user: recommendation.reverted_by.name, time } })
        : t_i18n('Reverted {time}', { values: { time } }),
      date: recommendation.reverted_at,
    };
  } else if (recommendation.status === 'dismissed' && recommendation.dismissed_at) {
    const time = rd(recommendation.dismissed_at);
    history = {
      sentence: recommendation.dismissed_by
        ? t_i18n('Dismissed by {user} {time}', { values: { user: recommendation.dismissed_by.name, time } })
        : t_i18n('Dismissed {time}', { values: { time } }),
      date: recommendation.dismissed_at,
    };
  }

  return (
    <Card padding="small" data-testid={`source-recommendation-${recommendation.id}`}>
      <Stack direction="row" justifyContent="space-between" alignItems="flex-start" gap={2}>
        <Box sx={{ minWidth: 0, flex: 1 }}>
          <Stack direction="row" gap={1} alignItems="center" flexWrap="wrap" sx={{ marginBottom: 1 }}>
            <Chip severity="neutral" size="sm" label={t_i18n(RECOMMENDATION_KIND_LABELS[recommendation.kind] ?? 'Recommendation')} />
            <Chip severity={STATUS_SEVERITIES[recommendation.status] ?? 'neutral'} size="sm" label={t_i18n(RECOMMENDATION_STATUS_LABELS[recommendation.status] ?? 'Proposed')} />
            {!hideSource && recommendation.source && (
              <Link to={`/dashboard/integrations/sources/source/${recommendation.source.id}`}>
                {recommendation.source.name}
              </Link>
            )}
            <Tooltip>
              <TooltipTrigger asChild>
                <Typography variant="caption" tabIndex={0} sx={{ color: theme.palette.text.secondary }}>
                  {t_i18n('Proposed {time}', { values: { time: rd(recommendation.proposed_at) } })}
                </Typography>
              </TooltipTrigger>
              <TooltipContent>{fldt(recommendation.proposed_at)}</TooltipContent>
            </Tooltip>
          </Stack>
          <Typography variant="body2">{recommendation.rationale}</Typography>
          {changes.map((change) => (
            <Typography key={change} variant="body2" sx={{ marginTop: 0.5, color: theme.palette.text.secondary }}>{change}</Typography>
          ))}
          {history && (
            <Tooltip>
              <TooltipTrigger asChild>
                <Typography variant="caption" component="div" tabIndex={0} sx={{ marginTop: 1, color: theme.palette.text.secondary, width: 'fit-content' }}>
                  {history.sentence}
                </Typography>
              </TooltipTrigger>
              <TooltipContent>{fldt(history.date)}</TooltipContent>
            </Tooltip>
          )}
          {recommendation.status === 'dismissed' && recommendation.dismiss_reason && (
            <Typography variant="caption" component="div" sx={{ color: theme.palette.text.secondary }}>
              {t_i18n('Reason: {reason}', { values: { reason: recommendation.dismiss_reason } })}
            </Typography>
          )}
          {recommendation.apply_result && recommendation.status === 'applied' && (
            <Typography variant="caption" component="div" sx={{ color: theme.palette.text.secondary }}>{recommendation.apply_result}</Typography>
          )}
          {recommendation.status === 'failed' && (
            <Box sx={{ marginTop: 1 }}>
              <Alert
                severity="error"
                title={t_i18n('The recommendation could not be applied.')}
                description={recommendation.error_message ?? t_i18n('The activity logs give the cause of the failure.')}
                action={canManage ? (
                  <Button variant="secondary" size="small" onClick={handleApply} disabled={busy} data-testid="source-recommendation-retry">
                    {catalogSlug ? t_i18n('Deploy again') : t_i18n('Apply again')}
                  </Button>
                ) : undefined}
              />
            </Box>
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
                  {details.map(({ key, label, value }) => (
                    <React.Fragment key={key}>
                      <Typography component="dt" variant="caption" sx={{ color: theme.palette.text.secondary }}>{label}</Typography>
                      <Typography component="dd" variant="caption" sx={{ margin: 0, wordBreak: 'break-word' }}>{value}</Typography>
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
            {recommendation.status === 'proposed' && (
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
              <Button variant="secondary" size="small" startIcon={<UndoOutlined />} onClick={() => setRevertOpen(true)} disabled={busy} data-testid="source-recommendation-revert">
                {t_i18n('Revert')}
              </Button>
            )}
          </Stack>
        )}
      </Stack>
      <Dialog open={revertOpen} onClose={() => setRevertOpen(false)} title={t_i18n('Revert this recommendation?')} size="small">
        <Typography variant="body2" sx={{ marginBottom: 1 }}>
          {t_i18n('Reverting restores the state before the recommendation was applied and removes what it created. A quarantine draft is kept for review.')}
        </Typography>
        {changes.map((change) => (
          <Typography key={change} variant="body2" sx={{ color: theme.palette.text.secondary }}>{change}</Typography>
        ))}
        <FormButtonContainer>
          <Button variant="secondary" onClick={() => setRevertOpen(false)} disabled={reverting}>{t_i18n('Cancel')}</Button>
          <Button onClick={handleRevert} disabled={reverting} data-testid="source-recommendation-revert-confirm">{t_i18n('Revert')}</Button>
        </FormButtonContainer>
      </Dialog>
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
