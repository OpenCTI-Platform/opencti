import React, { ReactNode } from 'react';
import Box from '@mui/material/Box';
import type SvgIcon from '@mui/material/SvgIcon';
import { alpha, type SxProps, useTheme } from '@mui/material/styles';
import FingerprintOutlined from '@mui/icons-material/FingerprintOutlined';
import LockOutlined from '@mui/icons-material/LockOutlined';
import MonitorHeartOutlined from '@mui/icons-material/MonitorHeartOutlined';
import UpdateOutlined from '@mui/icons-material/UpdateOutlined';
import { Text } from '@filigran/design-system';
import Label from '@common/label/Label';
import { useFormatter } from '../../../../components/i18n';
import type { ThreatPulseCardQuery } from './__generated__/ThreatPulseCardQuery.graphql';
import { ThreatPulsePrevalenceChip, ThreatPulseTrendChip } from './ThreatPulseChips';
import ThreatPulseDate from './ThreatPulseDate';
import ThreatPulseNotice from './ThreatPulseNotice';
import ThreatPulseTrendChart from './ThreatPulseTrendChart';
import ThreatPulseUniquenessMeter from './ThreatPulseUniquenessMeter';
import { ThreatPulseUnlockCta } from './ThreatPulseUnlock';
import { isPulseSectorDisclosed, PULSE_TREND_SENTENCES, pulseObservedHeadline, pulsePlatformsBucketLabel, pulseSectorLabel, pulseUniquenessMeaning } from './threatPulseUtils';

type PulseEntity = ThreatPulseCardQuery['response']['pulseEntity'];
export type PulseInformation = NonNullable<PulseEntity['information']>;

// Two to three facts side by side in a half-width column, one under the other in a narrow one.
export const THREAT_PULSE_FACTS_GRID_SX: SxProps = {
  display: 'grid',
  gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
  columnGap: 3,
  rowGap: 2,
};

export const THREAT_PULSE_FOOTER_SX = {
  paddingTop: 1.5,
  borderTop: '1px solid var(--border-elevation-subtle-soft-layer-1-transparency-15)',
};

const ThreatPulseFact = ({ label, children }: { label: string; children: ReactNode }) => (
  <Box sx={{ minWidth: 0 }}>
    <Label>{label}</Label>
    {children}
  </Box>
);

// The framed icon that opens a signal: the brand tone for a published signal, a neutral one otherwise.
const ThreatPulseSignalIcon = ({ icon: SignalIcon, muted = false }: { icon: typeof SvgIcon; muted?: boolean }) => {
  const theme = useTheme();
  return (
    <Box
      aria-hidden
      sx={{
        width: 36,
        height: 36,
        flexShrink: 0,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        borderRadius: 1,
        color: muted ? theme.palette.text.secondary : theme.palette.primary.main,
        backgroundColor: muted ? alpha(theme.palette.text.primary, 0.06) : alpha(theme.palette.primary.main, 0.12),
      }}
    >
      <SignalIcon sx={{ fontSize: 20 }} />
    </Box>
  );
};

const ThreatPulseHeadline = ({ children }: { children: string }) => (
  <Text variant="title-xs" as="p" data-testid="threat-pulse-headline">{children}</Text>
);

interface ThreatPulseFreshnessProps {
  updatedAt?: string | null;
  // Why the information may be stale (XTM Hub out of reach, rate limited), already translated.
  notice?: string | null;
  noticeIcon?: typeof SvgIcon;
}

// The footer of every signal: when XTM Hub last refreshed it, and why it may be stale.
export const ThreatPulseFreshness = ({ updatedAt, notice, noticeIcon: NoticeIcon = UpdateOutlined }: ThreatPulseFreshnessProps) => {
  const theme = useTheme();
  const { t_i18n } = useFormatter();
  if (!updatedAt && !notice) {
    return null;
  }
  const secondary = { color: theme.palette.text.secondary };
  return (
    <Box
      component="footer"
      data-testid="threat-pulse-freshness"
      sx={{ display: 'flex', flexDirection: 'column', gap: 0.5, ...THREAT_PULSE_FOOTER_SX }}
    >
      {notice && (
        <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 0.75 }}>
          <NoticeIcon aria-hidden sx={{ fontSize: 16, marginTop: '1px', color: theme.palette.text.secondary }} />
          <Text variant="content-compact" style={secondary} data-testid="threat-pulse-unavailable">{notice}</Text>
        </Box>
      )}
      {updatedAt && (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
          <UpdateOutlined aria-hidden sx={{ fontSize: 16, color: theme.palette.text.secondary }} />
          <ThreatPulseDate date={updatedAt} format={(date) => t_i18n('Updated {date}', { values: { date } })} style={secondary} />
        </Box>
      )}
    </Box>
  );
};

interface ThreatPulsePublishedSignalProps {
  information: PulseInformation;
  sectorBucket?: string | null;
  footer: ReactNode;
}

// The object reached the anonymity threshold: how many platforms observed it, how that moves, and what it means.
export const ThreatPulsePublishedSignal = ({ information, sectorBucket, footer }: ThreatPulsePublishedSignalProps) => {
  const theme = useTheme();
  const { t_i18n } = useFormatter();
  const secondary = { color: theme.palette.text.secondary };
  const series = information.trend_series;
  const hasChart = series.length >= 2 && series.some((value) => value > 0);
  const sectorPlatforms = pulsePlatformsBucketLabel(t_i18n, information.sector_platforms_bucket);
  const showSector = isPulseSectorDisclosed(sectorBucket) || !!information.sector_trend;
  const uniqueness = information.community_uniqueness;
  return (
    <Box data-testid="threat-pulse-card" sx={{ display: 'flex', flexDirection: 'column', gap: 2.5 }}>
      <Box sx={{ display: 'flex', alignItems: 'flex-start', flexWrap: 'wrap', columnGap: 3, rowGap: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 2, flex: '1 1 260px', minWidth: 0 }}>
          <ThreatPulseSignalIcon icon={MonitorHeartOutlined} />
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, minWidth: 0 }}>
            <ThreatPulseHeadline>{pulseObservedHeadline(t_i18n, information.platforms_bucket)}</ThreatPulseHeadline>
            {(information.prevalence || information.trend) && (
              <Box sx={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 1 }}>
                {information.prevalence && <ThreatPulsePrevalenceChip prevalence={information.prevalence} />}
                {information.trend && <ThreatPulseTrendChip trend={information.trend} testId="threat-pulse-community-trend" />}
              </Box>
            )}
            {information.trend && PULSE_TREND_SENTENCES[information.trend] && (
              <Text variant="content-compact" style={secondary}>{t_i18n(PULSE_TREND_SENTENCES[information.trend])}</Text>
            )}
          </Box>
        </Box>
        {hasChart && (
          <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 0.5, marginLeft: 'auto' }}>
            <ThreatPulseTrendChart
              series={series}
              label={t_i18n('Contributing platforms per week, last {count} weeks', { values: { count: series.length } })}
            />
            <Text as="span" variant="content-caption" style={secondary}>
              {t_i18n('Last {count} weeks', { values: { count: series.length } })}
            </Text>
          </Box>
        )}
      </Box>
      {(information.first_seen_network || information.last_seen_network || showSector) && (
        <Box sx={THREAT_PULSE_FACTS_GRID_SX} data-testid="threat-pulse-facts">
          {information.first_seen_network && (
            <ThreatPulseFact label={t_i18n('Network first seen')}>
              <ThreatPulseDate date={information.first_seen_network} precision="day" variant="content-base" />
            </ThreatPulseFact>
          )}
          {information.last_seen_network && (
            <ThreatPulseFact label={t_i18n('Network last seen')}>
              <ThreatPulseDate date={information.last_seen_network} precision="day" variant="content-base" />
            </ThreatPulseFact>
          )}
          {showSector && (
            <ThreatPulseFact label={t_i18n('Sector trend ({sector})', { values: { sector: pulseSectorLabel(t_i18n, sectorBucket) } })}>
              {information.sector_trend ? (
                <Box sx={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 1 }}>
                  <ThreatPulseTrendChip trend={information.sector_trend} testId="threat-pulse-sector-trend" />
                  {sectorPlatforms && <Text as="span" variant="content-compact" style={secondary}>{sectorPlatforms}</Text>}
                </Box>
              ) : (
                <Text variant="content-compact" style={secondary}>{t_i18n('Below the anonymity threshold')}</Text>
              )}
            </ThreatPulseFact>
          )}
        </Box>
      )}
      {uniqueness !== null && uniqueness !== undefined && (
        <ThreatPulseUniquenessMeter score={uniqueness} meaning={t_i18n(pulseUniquenessMeaning(uniqueness))} />
      )}
      {footer}
    </Box>
  );
};

// Fewer platforms than the anonymity threshold observed the object: a short, quiet statement, never an empty panel.
export const ThreatPulseBelowThreshold = ({ information, footer }: { information: PulseInformation; footer: ReactNode }) => {
  const theme = useTheme();
  const { t_i18n } = useFormatter();
  const uniqueness = information.community_uniqueness;
  return (
    <Box data-testid="threat-pulse-card" sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
      <Box data-testid="threat-pulse-below-threshold" sx={{ display: 'flex', alignItems: 'flex-start', gap: 2 }}>
        <ThreatPulseSignalIcon icon={FingerprintOutlined} muted />
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5, minWidth: 0 }}>
          <ThreatPulseHeadline>{t_i18n('Rare, or unique to this platform')}</ThreatPulseHeadline>
          <Text variant="content-compact" style={{ color: theme.palette.text.secondary }}>
            {t_i18n('Fewer platforms than the anonymity threshold observed this object: the community publishes no count or trend for it.')}
          </Text>
        </Box>
      </Box>
      {uniqueness !== null && uniqueness !== undefined && <ThreatPulseUniquenessMeter score={uniqueness} />}
      {footer}
    </Box>
  );
};

// The rows of the full experience, folded into one line with the one step that unlocks them.
const ThreatPulseLockedLine = () => {
  const theme = useTheme();
  const { t_i18n } = useFormatter();
  return (
    <Box sx={{ padding: 1.5, borderRadius: 1, backgroundColor: theme.palette.action.hover }}>
      <ThreatPulseNotice
        icon={LockOutlined}
        testId="threat-pulse-locked"
        message={t_i18n('Contributing platforms, network first seen, 12-week trend and sector trend: available when your platform contributes.')}
        action={<ThreatPulseUnlockCta surface="entity_card" />}
      />
    </Box>
  );
};

// Preview: the coarse signal of the daily digest when the object is in it, and what contributing adds.
export const ThreatPulsePreviewSignal = ({ information }: { information: PulseInformation | null }) => {
  const { t_i18n } = useFormatter();
  return (
    <Box data-testid="threat-pulse-preview" sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
      {information ? (
        <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 2 }}>
          <ThreatPulseSignalIcon icon={MonitorHeartOutlined} muted />
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, minWidth: 0 }}>
            <ThreatPulseHeadline>{t_i18n('Among the most prevalent objects of the community')}</ThreatPulseHeadline>
            <Box sx={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 1 }}>
              {information.prevalence && <ThreatPulsePrevalenceChip prevalence={information.prevalence} />}
              {information.trend && <ThreatPulseTrendChip trend={information.trend} testId="threat-pulse-community-trend" />}
            </Box>
          </Box>
        </Box>
      ) : (
        <ThreatPulseNotice
          icon={MonitorHeartOutlined}
          testId="threat-pulse-preview-not-listed"
          message={t_i18n('This object is not among the most prevalent objects of the community today.')}
        />
      )}
      <ThreatPulseLockedLine />
      {information?.updated_at && <ThreatPulseFreshness updatedAt={information.updated_at} />}
    </Box>
  );
};
