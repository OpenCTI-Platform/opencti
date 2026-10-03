import React, { ReactNode, Suspense, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Link } from 'react-router';
import Box from '@mui/material/Box';
import { useTheme } from '@mui/styles';
import { Chip, Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Spinner, Text } from '@filigran/design-system';
import Card from '@common/card/Card';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { resolveLink } from '../../../../utils/Entity';
import { ThreatPulseTrendingQuery } from './__generated__/ThreatPulseTrendingQuery.graphql';
import ThreatPulseBriefing from './ThreatPulseBriefing';
import { ThreatPulseLockedRow, ThreatPulsePreviewChip, ThreatPulseUnlockCta, useThreatPulseImpression } from './ThreatPulseUnlock';
import {
  formatPulseGrowth,
  PULSE_PERIOD_LABELS,
  PULSE_PERIODS,
  PULSE_PREVALENCE_LABELS,
  PULSE_SECTOR_LABELS,
  PULSE_TREND_LABELS,
  PULSE_TREND_SEVERITIES,
  PULSE_UNAVAILABLE_MESSAGES,
  type PulsePeriodValue,
} from './threatPulseUtils';

export const threatPulseTrendingQuery = graphql`
  query ThreatPulseTrendingQuery($period: PulsePeriod!, $first: Int) {
    pulseTrending(period: $period, first: $first, include_preview: true) {
      readable
      preview
      unavailable_reason
      day
      period
      sector_bucket
      region_bucket
      network_items_count
      locked_count
      entries {
        object_type
        rank
        platforms_bucket
        prevalence
        trend
        growth
        first_seen_network
        entity {
          id
          entity_type
          representative {
            main
          }
        }
      }
    }
  }
`;

const ELLIPSIS = { overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } as const;

interface ThreatPulseTrendingListProps {
  period: PulsePeriodValue;
  first: number;
}

const ThreatPulseTrendingList = ({ period, first }: ThreatPulseTrendingListProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fsd } = useFormatter();
  const { pulseTrending } = useLazyLoadQuery<ThreatPulseTrendingQuery>(
    threatPulseTrendingQuery,
    { period, first },
    { fetchPolicy: 'store-and-network' },
  );
  const secondary = { color: theme.palette.text.secondary };
  useThreatPulseImpression('trending_widget', pulseTrending.preview);
  if (!pulseTrending.readable) {
    return (
      <Text variant="content-compact" style={secondary} data-testid="threat-pulse-trending-unavailable">
        {t_i18n(PULSE_UNAVAILABLE_MESSAGES[pulseTrending.unavailable_reason ?? 'not_enabled'] ?? 'Threat Pulse is not enabled on this platform.')}
      </Text>
    );
  }
  const notHeld = Math.max(0, pulseTrending.network_items_count - pulseTrending.entries.length);
  const sectorLabel = pulseTrending.sector_bucket
    ? t_i18n(PULSE_SECTOR_LABELS[pulseTrending.sector_bucket] ?? 'Undisclosed')
    : t_i18n('Every sector');
  if (pulseTrending.preview) {
    return (
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }} data-testid="threat-pulse-trending-preview">
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
          <ThreatPulsePreviewChip />
          <Text variant="content-compact" style={secondary}>{`${t_i18n('Sector')}: ${sectorLabel} - ${t_i18n('Last 7 days')}`}</Text>
        </Box>
        <Box component="ul" sx={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 0.5 }}>
          {pulseTrending.entries.map((entry) => {
            const link = resolveLink(entry.entity.entity_type);
            const name = <Text variant="content-compact" style={ELLIPSIS}>{entry.entity.representative.main}</Text>;
            return (
              <Box component="li" key={entry.entity.id} sx={{ display: 'flex', alignItems: 'center', gap: 1.5, paddingY: 0.75 }}>
                <Text variant="content-compact" style={secondary}>{`#${entry.rank ?? '-'}`}</Text>
                <ItemIcon type={entry.entity.entity_type} />
                <Box sx={{ flex: 1, minWidth: 0 }}>
                  {link ? <Link to={`${link}/${entry.entity.id}`} style={{ color: 'inherit' }}>{name}</Link> : name}
                  <Text variant="content-compact" style={secondary}>{t_i18n(PULSE_PREVALENCE_LABELS[entry.prevalence])}</Text>
                </Box>
                <Chip label={t_i18n(PULSE_TREND_LABELS[entry.trend])} severity={PULSE_TREND_SEVERITIES[entry.trend]} />
              </Box>
            );
          })}
        </Box>
        {notHeld > 0 && (
          <Text variant="content-compact" style={secondary}>
            {`${notHeld} ${t_i18n('of the first ranks trend in the community, but this platform does not hold them.')}`}
          </Text>
        )}
        {Array.from({ length: pulseTrending.locked_count }, (_, index) => (
          <ThreatPulseLockedRow key={index} label={`#${pulseTrending.network_items_count + index + 1} ${t_i18n('Trending object')}`} />
        ))}
        <Box sx={{ display: 'flex', justifyContent: 'flex-start', paddingTop: 0.5 }}>
          <ThreatPulseUnlockCta surface="trending_widget" />
        </Box>
      </Box>
    );
  }
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }} data-testid="threat-pulse-trending-list">
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 1, flexWrap: 'wrap' }}>
        <Text variant="content-compact" style={secondary}>
          {`${t_i18n('Sector')}: ${sectorLabel}`}
        </Text>
        <ThreatPulseBriefing period={period} sectorBucket={pulseTrending.sector_bucket} regionBucket={pulseTrending.region_bucket} />
      </Box>
      {pulseTrending.entries.length === 0 && (
        <Text variant="content-compact" style={secondary}>
          {t_i18n('Nothing this platform holds is trending in its sector for this period.')}
        </Text>
      )}
      <Box component="ul" sx={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 0.5 }}>
        {pulseTrending.entries.map((entry) => {
          const link = resolveLink(entry.entity.entity_type);
          const name = <Text variant="content-compact" style={ELLIPSIS}>{entry.entity.representative.main}</Text>;
          return (
            <Box
              component="li"
              key={entry.entity.id}
              sx={{ display: 'flex', alignItems: 'center', gap: 1.5, paddingY: 0.75, borderBottom: '1px solid var(--border-elevation-subtle-soft-layer-1-transparency-15)' }}
            >
              <ItemIcon type={entry.entity.entity_type} />
              <Box sx={{ flex: 1, minWidth: 0 }}>
                {link ? <Link to={`${link}/${entry.entity.id}`} style={{ color: 'inherit' }}>{name}</Link> : name}
                <Text variant="content-compact" style={secondary}>
                  {`${t_i18n('Network first seen')} ${entry.first_seen_network ? fsd(entry.first_seen_network) : '-'} - ${t_i18n(PULSE_PREVALENCE_LABELS[entry.prevalence])}`}
                </Text>
              </Box>
              <Text variant="content-compact" style={secondary} title={t_i18n('Contributing platforms')}>{entry.platforms_bucket ?? '-'}</Text>
              <Chip label={entry.growth !== null && entry.growth !== undefined ? formatPulseGrowth(entry.growth) : '-'} severity="info" />
              <Chip label={t_i18n(PULSE_TREND_LABELS[entry.trend])} severity={PULSE_TREND_SEVERITIES[entry.trend]} />
            </Box>
          );
        })}
      </Box>
      {notHeld > 0 && (
        <Text variant="content-compact" style={secondary}>
          {`${notHeld} ${t_i18n('more items trend in the sector, but this platform does not hold them.')}`}
        </Text>
      )}
    </Box>
  );
};

interface ThreatPulseTrendingProps {
  title?: string;
  first?: number;
  popover?: ReactNode;
}

/**
 * "Trending in your sector": local objects rising in the platform's sector bucket on Threat Pulse. Used as a home
 * widget and as a custom dashboard widget.
 */
const ThreatPulseTrending = ({ title, first = 10, popover }: ThreatPulseTrendingProps) => {
  const { t_i18n } = useFormatter();
  const [period, setPeriod] = useState<PulsePeriodValue>('last_7_days');
  const action = (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
      <Select value={period} onValueChange={(value) => setPeriod(value as PulsePeriodValue)}>
        <SelectTrigger aria-label={t_i18n('Period')} style={{ width: 140 }}>
          <SelectValue>{t_i18n(PULSE_PERIOD_LABELS[period])}</SelectValue>
        </SelectTrigger>
        <SelectContent aria-label={t_i18n('Period')}>
          {PULSE_PERIODS.map((value) => (
            <SelectItem key={value} value={value}>{t_i18n(PULSE_PERIOD_LABELS[value])}</SelectItem>
          ))}
        </SelectContent>
      </Select>
      {popover}
    </Box>
  );
  return (
    <Card title={title ?? t_i18n('Trending in your sector')} action={action}>
      <div data-testid="threat-pulse-trending">
        <Suspense fallback={<Spinner label={t_i18n('Loading')} />}>
          <ThreatPulseTrendingList period={period} first={first} />
        </Suspense>
      </div>
    </Card>
  );
};

export default ThreatPulseTrending;
