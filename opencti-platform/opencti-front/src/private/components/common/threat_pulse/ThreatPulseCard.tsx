import React, { Suspense } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import Grid from '@mui/material/Grid';
import Box from '@mui/material/Box';
import { alpha } from '@mui/material/styles';
import { useTheme } from '@mui/styles';
import { Chip, Text, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { InformationOutline } from 'mdi-material-ui';
import Card from '@common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { ThreatPulseCardQuery } from './__generated__/ThreatPulseCardQuery.graphql';
import {
  buildSparklinePoints,
  PULSE_PREVALENCE_LABELS,
  PULSE_PREVALENCE_ORDER,
  PULSE_SECTOR_LABELS,
  PULSE_TREND_LABELS,
  PULSE_TREND_SEVERITIES,
  PULSE_UNAVAILABLE_MESSAGES,
} from './threatPulseUtils';

export const threatPulseCardQuery = graphql`
  query ThreatPulseCardQuery($id: ID!) {
    pulseEntity(id: $id) {
      id
      readable
      unavailable_reason
      sector_bucket
      information {
        published
        prevalence
        platforms_bucket
        first_seen_network
        last_seen_network
        trend
        trend_series
        sector_trend
        sector_platforms_bucket
        community_uniqueness
        updated_at
      }
    }
  }
`;

// Reasons for which the card is not displayed at all: Threat Pulse is off or does not apply to the entity.
const HIDDEN_REASONS = ['not_enabled', 'out_of_scope'];
const SPARKLINE_WIDTH = 160;
const SPARKLINE_HEIGHT = 36;

const PrevalenceGauge = ({ prevalence }: { prevalence: string }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const activeIndex = PULSE_PREVALENCE_ORDER.indexOf(prevalence as typeof PULSE_PREVALENCE_ORDER[number]);
  const label = t_i18n(PULSE_PREVALENCE_LABELS[prevalence] ?? prevalence);
  return (
    <Box
      role="meter"
      aria-label={t_i18n('Community prevalence')}
      aria-valuemin={0}
      aria-valuemax={PULSE_PREVALENCE_ORDER.length - 1}
      aria-valuenow={Math.max(activeIndex, 0)}
      aria-valuetext={label}
      data-testid="threat-pulse-prevalence-gauge"
      sx={{ display: 'flex', gap: 0.5, width: '100%' }}
    >
      {PULSE_PREVALENCE_ORDER.map((bucket, index) => (
        <Box key={bucket} sx={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 0.5 }}>
          <Box
            sx={{
              height: 8,
              borderRadius: 1,
              backgroundColor: index <= activeIndex
                ? alpha(theme.palette.primary.main, 0.35 + (index * 0.65) / (PULSE_PREVALENCE_ORDER.length - 1))
                : alpha(theme.palette.text.primary, 0.08),
            }}
          />
          <Text
            variant={index === activeIndex ? 'content-compact-bold' : 'content-compact'}
            style={{ color: index === activeIndex ? theme.palette.text.primary : theme.palette.text.secondary }}
          >
            {t_i18n(PULSE_PREVALENCE_LABELS[bucket])}
          </Text>
        </Box>
      ))}
    </Box>
  );
};

export const PulseSparkline = ({ series, label }: { series: readonly number[]; label: string }) => {
  const theme = useTheme<Theme>();
  if (series.length === 0 || series.every((value) => value === 0)) {
    return null;
  }
  return (
    <svg
      role="img"
      aria-label={label}
      width={SPARKLINE_WIDTH}
      height={SPARKLINE_HEIGHT}
      viewBox={`0 0 ${SPARKLINE_WIDTH} ${SPARKLINE_HEIGHT}`}
      data-testid="threat-pulse-sparkline"
    >
      <polyline
        fill="none"
        stroke={theme.palette.primary.main}
        strokeWidth={2}
        strokeLinejoin="round"
        strokeLinecap="round"
        points={buildSparklinePoints(series, SPARKLINE_WIDTH, SPARKLINE_HEIGHT)}
      />
    </svg>
  );
};

const DetailRow = ({ label, children }: { label: string; children: React.ReactNode }) => {
  const theme = useTheme<Theme>();
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 2, minHeight: 32 }}>
      <Text variant="content-compact" style={{ color: theme.palette.text.secondary }}>{label}</Text>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>{children}</Box>
    </Box>
  );
};

interface ThreatPulseCardProps {
  entityId: string;
}

const ThreatPulseCardComponent = ({ entityId }: ThreatPulseCardProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fsd, fldt } = useFormatter();
  const { pulseEntity } = useLazyLoadQuery<ThreatPulseCardQuery>(threatPulseCardQuery, { id: entityId }, { fetchPolicy: 'store-and-network' });
  if (!pulseEntity.readable && HIDDEN_REASONS.includes(pulseEntity.unavailable_reason ?? '')) {
    return null;
  }
  const secondary = { color: theme.palette.text.secondary };
  const information = pulseEntity.information;
  const reason = pulseEntity.unavailable_reason;
  const title = (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
      {t_i18n('Threat Pulse')}
      <Tooltip>
        <TooltipTrigger asChild>
          <span aria-label={t_i18n('About Threat Pulse')} style={{ display: 'inline-flex' }}>
            <InformationOutline fontSize="small" color="primary" />
          </span>
        </TooltipTrigger>
        <TooltipContent>
          {t_i18n('Community signal from the platforms contributing to Threat Pulse: keyed hashes and counts only, published when at least the anonymity threshold of platforms observed the same object.')}
        </TooltipContent>
      </Tooltip>
    </Box>
  );
  return (
    <Grid item xs={6}>
      <Card title={title}>
        <Box data-testid="threat-pulse-card" sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
          {reason && (
            <Text variant="content-compact" style={secondary} data-testid="threat-pulse-unavailable">
              {t_i18n(PULSE_UNAVAILABLE_MESSAGES[reason] ?? reason)}
            </Text>
          )}
          {information && (
            <>
              <PrevalenceGauge prevalence={information.prevalence ?? 'rare'} />
              {!information.published && (
                <Text variant="content-compact" style={secondary}>
                  {t_i18n('Fewer platforms than the anonymity threshold observed this object: it is rare, or unique to this platform.')}
                </Text>
              )}
              {information.published && (
                <>
                  <DetailRow label={t_i18n('Contributing platforms')}>
                    <Chip label={information.platforms_bucket ?? '-'} severity="info" />
                  </DetailRow>
                  <DetailRow label={t_i18n('Network first seen')}>
                    <Text variant="content-compact">{information.first_seen_network ? fsd(information.first_seen_network) : '-'}</Text>
                  </DetailRow>
                  <DetailRow label={t_i18n('Network last seen')}>
                    <Text variant="content-compact">{information.last_seen_network ? fsd(information.last_seen_network) : '-'}</Text>
                  </DetailRow>
                  <DetailRow label={t_i18n('Community trend')}>
                    <PulseSparkline series={information.trend_series} label={t_i18n('Contributing platforms per week, last 12 weeks')} />
                    {information.trend && (
                      <Chip label={t_i18n(PULSE_TREND_LABELS[information.trend])} severity={PULSE_TREND_SEVERITIES[information.trend]} />
                    )}
                  </DetailRow>
                  <DetailRow label={`${t_i18n('Sector trend')} (${t_i18n(PULSE_SECTOR_LABELS[pulseEntity.sector_bucket ?? 'undisclosed'] ?? 'Undisclosed')})`}>
                    {information.sector_trend ? (
                      <>
                        <Text variant="content-compact" style={secondary}>{information.sector_platforms_bucket}</Text>
                        <Chip label={t_i18n(PULSE_TREND_LABELS[information.sector_trend])} severity={PULSE_TREND_SEVERITIES[information.sector_trend]} />
                      </>
                    ) : (
                      <Text variant="content-compact" style={secondary}>{t_i18n('Below the anonymity threshold')}</Text>
                    )}
                  </DetailRow>
                </>
              )}
              <DetailRow label={t_i18n('Community uniqueness')}>
                <Text variant="content-compact">
                  {information.community_uniqueness !== null && information.community_uniqueness !== undefined ? `${information.community_uniqueness} / 100` : '-'}
                </Text>
              </DetailRow>
              {information.updated_at && (
                <Text variant="content-compact" style={secondary}>
                  {`${t_i18n('Updated')} ${fldt(information.updated_at)}`}
                </Text>
              )}
            </>
          )}
          {!information && !reason && (
            <Text variant="content-compact" style={secondary}>{t_i18n('No Threat Pulse information for this object yet.')}</Text>
          )}
        </Box>
      </Card>
    </Grid>
  );
};

/**
 * Threat Pulse card of an entity overview: renders its own grid item, and nothing when Threat Pulse is off or does
 * not apply to the entity, so that it never takes room on platforms that did not opt in.
 */
const ThreatPulseCard = ({ entityId }: ThreatPulseCardProps) => (
  <Suspense fallback={null}>
    <ThreatPulseCardComponent entityId={entityId} />
  </Suspense>
);

export default ThreatPulseCard;
