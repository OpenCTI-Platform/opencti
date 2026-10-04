import React, { Suspense } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import Box from '@mui/material/Box';
import { alpha } from '@mui/material/styles';
import { useTheme } from '@mui/styles';
import { Chip, Text, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { InformationOutline } from 'mdi-material-ui';
import Card from '@common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import useAuth from '../../../../utils/hooks/useAuth';
import { ThreatPulseConnectCta, ThreatPulseLockedRow, ThreatPulsePreviewChip, ThreatPulseUnlockCta, useThreatPulseImpression } from './ThreatPulseUnlock';
import ThreatPulseDate from './ThreatPulseDate';
import { ThreatPulseCardQuery } from './__generated__/ThreatPulseCardQuery.graphql';
import {
  buildSparklinePoints,
  PULSE_PREVALENCE_LABELS,
  PULSE_PREVALENCE_ORDER,
  PULSE_SECTOR_LABELS,
  PULSE_TREND_LABELS,
  PULSE_TREND_SEVERITIES,
  PULSE_UNAVAILABLE_MESSAGES,
  pulsePlatformsBucketLabel,
} from './threatPulseUtils';

export const threatPulseCardQuery = graphql`
  query ThreatPulseCardQuery($id: ID!) {
    pulseEntity(id: $id) {
      id
      access
      readable
      unavailable_reason
      sector_bucket
      information {
        published
        preview
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
                ? alpha(theme.palette.designSystem.primary.main, 0.35 + (index * 0.65) / (PULSE_PREVALENCE_ORDER.length - 1))
                : theme.palette.designSystem.border.main,
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

const ThreatPulseCardTitle = ({ preview = false }: { preview?: boolean }) => {
  const { t_i18n } = useFormatter();
  return (
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
      {preview && <ThreatPulsePreviewChip />}
    </Box>
  );
};

// Not connected to XTM Hub: what Threat Pulse would add, and the one step to get it.
const ThreatPulseNotConnectedCard = () => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  useThreatPulseImpression('entity_card', true);
  return (
    <Box sx={{ flex: '0 0 auto' }} data-testid="threat-pulse-card-container">
      <Card title={<ThreatPulseCardTitle />} fullHeight={false}>
        <Box data-testid="threat-pulse-not-connected" sx={{ display: 'flex', flexDirection: 'column', gap: 1.5, alignItems: 'flex-start' }}>
          <Text variant="content-compact" style={{ color: theme.palette.text.secondary }}>
            {t_i18n('Connect the platform to XTM Hub to see how widespread this object is across the OpenCTI community and whether it is rising, without sending anything about it.')}
          </Text>
          <ThreatPulseConnectCta surface="entity_card" />
        </Box>
      </Card>
    </Box>
  );
};

type PulseEntity = ThreatPulseCardQuery['response']['pulseEntity'];

// Preview: the real coarse signal of the digest when the object is among the most prevalent of the community, the
// rows of the full experience locked, and the one step to unlock them.
const ThreatPulsePreviewCard = ({ pulseEntity }: { pulseEntity: PulseEntity }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  useThreatPulseImpression('entity_card', true);
  const secondary = { color: theme.palette.text.secondary };
  const information = pulseEntity.information?.preview ? pulseEntity.information : null;
  return (
    <Box sx={{ flex: '0 0 auto' }} data-testid="threat-pulse-card-container">
      <Card title={<ThreatPulseCardTitle preview />} fullHeight={false}>
        <Box data-testid="threat-pulse-preview" sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
          {information ? (
            <>
              {information.prevalence && <PrevalenceGauge prevalence={information.prevalence} />}
              {information.trend && (
                <DetailRow label={t_i18n('Community trend')}>
                  <Chip label={t_i18n(PULSE_TREND_LABELS[information.trend])} severity={PULSE_TREND_SEVERITIES[information.trend]} />
                </DetailRow>
              )}
            </>
          ) : (
            <Text variant="content-compact" style={secondary} data-testid="threat-pulse-preview-not-listed">
              {t_i18n('This object is not among the most prevalent objects of the community today.')}
            </Text>
          )}
          <ThreatPulseLockedRow label={t_i18n('Contributing platforms')} />
          <ThreatPulseLockedRow label={t_i18n('Network first seen')} />
          <ThreatPulseLockedRow label={t_i18n('Community trend over 12 weeks')} />
          <ThreatPulseLockedRow label={t_i18n('Sector trend')} />
          <Box sx={{ display: 'flex', justifyContent: 'flex-start' }}>
            <ThreatPulseUnlockCta surface="entity_card" />
          </Box>
          {information?.updated_at && (
            <Text variant="content-compact" style={secondary}>
              <ThreatPulseDate date={information.updated_at} format={(date) => t_i18n('Updated {date}', { values: { date } })} />
            </Text>
          )}
        </Box>
      </Card>
    </Box>
  );
};

const ThreatPulseCardComponent = ({ entityId }: ThreatPulseCardProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { settings } = useAuth();
  const { pulseEntity } = useLazyLoadQuery<ThreatPulseCardQuery>(threatPulseCardQuery, { id: entityId }, { fetchPolicy: 'store-and-network' });
  if (pulseEntity.unavailable_reason === 'out_of_scope') {
    return null;
  }
  if (pulseEntity.access === 'not_connected') {
    // Only where XTM Hub can be reached: an isolated platform is never asked to connect.
    return settings?.xtm_hub_backend_is_reachable ? <ThreatPulseNotConnectedCard /> : null;
  }
  if (pulseEntity.access === 'preview') {
    return <ThreatPulsePreviewCard pulseEntity={pulseEntity} />;
  }
  const information = pulseEntity.information;
  if (pulseEntity.access !== 'full' || !information) {
    return null;
  }
  const secondary = { color: theme.palette.text.secondary };
  const reason = pulseEntity.unavailable_reason;
  const title = <ThreatPulseCardTitle />;
  const platforms = pulsePlatformsBucketLabel(t_i18n, information.platforms_bucket);
  const sectorPlatforms = pulsePlatformsBucketLabel(t_i18n, information.sector_platforms_bucket);
  return (
    <Box sx={{ flex: '0 0 auto' }} data-testid="threat-pulse-card-container">
      <Card title={title} fullHeight={false}>
        <Box data-testid="threat-pulse-card" sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
          {reason && (
            <Text variant="content-compact" style={secondary} data-testid="threat-pulse-unavailable">
              {t_i18n(PULSE_UNAVAILABLE_MESSAGES[reason] ?? reason)}
            </Text>
          )}
          {/* A prevalence only when XTM Hub published one: below the anonymity threshold, the explanation alone */}
          {information.published && information.prevalence && <PrevalenceGauge prevalence={information.prevalence} />}
          {!information.published && (
            <Text variant="content-compact" style={secondary}>
              {t_i18n('Fewer platforms than the anonymity threshold observed this object: it is rare, or unique to this platform.')}
            </Text>
          )}
          {information.published && (
            <>
              {platforms && (
                <DetailRow label={t_i18n('Contributing platforms')}>
                  <Chip label={platforms} severity="info" />
                </DetailRow>
              )}
              {information.first_seen_network && (
                <DetailRow label={t_i18n('Network first seen')}>
                  <ThreatPulseDate date={information.first_seen_network} precision="day" />
                </DetailRow>
              )}
              {information.last_seen_network && (
                <DetailRow label={t_i18n('Network last seen')}>
                  <ThreatPulseDate date={information.last_seen_network} precision="day" />
                </DetailRow>
              )}
              <DetailRow label={t_i18n('Community trend')}>
                <PulseSparkline series={information.trend_series} label={t_i18n('Contributing platforms per week, last 12 weeks')} />
                {information.trend && (
                  <Chip label={t_i18n(PULSE_TREND_LABELS[information.trend])} severity={PULSE_TREND_SEVERITIES[information.trend]} />
                )}
              </DetailRow>
              <DetailRow label={t_i18n('Sector trend ({sector})', { values: { sector: t_i18n(PULSE_SECTOR_LABELS[pulseEntity.sector_bucket ?? 'undisclosed'] ?? 'Undisclosed') } })}>
                {information.sector_trend ? (
                  <>
                    {sectorPlatforms && <Text variant="content-compact" style={secondary}>{sectorPlatforms}</Text>}
                    <Chip label={t_i18n(PULSE_TREND_LABELS[information.sector_trend])} severity={PULSE_TREND_SEVERITIES[information.sector_trend]} />
                  </>
                ) : (
                  <Text variant="content-compact" style={secondary}>{t_i18n('Below the anonymity threshold')}</Text>
                )}
              </DetailRow>
            </>
          )}
          {information.community_uniqueness !== null && information.community_uniqueness !== undefined && (
            <DetailRow label={t_i18n('Community uniqueness')}>
              <Text variant="content-compact">{t_i18n('{score} out of 100', { values: { score: information.community_uniqueness } })}</Text>
            </DetailRow>
          )}
          {information.updated_at && (
            <Text variant="content-compact" style={secondary}>
              <ThreatPulseDate date={information.updated_at} format={(date) => t_i18n('Updated {date}', { values: { date } })} />
            </Text>
          )}
        </Box>
      </Card>
    </Box>
  );
};

/**
 * Threat Pulse card of an entity overview, in three states: not connected to XTM Hub (what it would add and how to
 * connect), preview (the coarse community signal and the locked rows of the full experience) and full. It renders
 * nothing when an administrator turned Threat Pulse off or the entity type is out of scope.
 */
const ThreatPulseCard = ({ entityId }: ThreatPulseCardProps) => (
  <Suspense fallback={null}>
    <ThreatPulseCardComponent entityId={entityId} />
  </Suspense>
);

export default ThreatPulseCard;
