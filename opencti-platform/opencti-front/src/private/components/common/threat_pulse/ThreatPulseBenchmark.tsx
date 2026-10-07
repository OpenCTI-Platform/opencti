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
import useEntityTranslation from '../../../../utils/hooks/useEntityTranslation';
import { resolveLink } from '../../../../utils/Entity';
import { ThreatPulseBenchmarkQuery } from './__generated__/ThreatPulseBenchmarkQuery.graphql';
import ThreatPulseEntityName from './ThreatPulseEntityName';
import { ThreatPulseLockedRow, ThreatPulsePreviewChip, ThreatPulseUnlockCta, useThreatPulseImpression } from './ThreatPulseUnlock';
import {
  formatPulseRatio,
  PULSE_EVENT_KIND_LABELS,
  PULSE_PERIOD_LABELS,
  PULSE_PERIODS,
  PULSE_SECTOR_LABELS,
  PULSE_UNAVAILABLE_MESSAGES,
  pulsePlatformsBucketLabel,
  pulseRatioSeverity,
  type PulsePeriodValue,
} from './threatPulseUtils';

export const threatPulseBenchmarkQuery = graphql`
  query ThreatPulseBenchmarkQuery($period: PulsePeriod!) {
    pulseBenchmark(period: $period) {
      readable
      unavailable_reason
      period
      sector_bucket
      region_bucket
      sector_platforms_bucket
      metrics {
        object_type
        event_kind
        platform_count
        sector_median
        network_median
        ratio
      }
      entries {
        object_type
        platform_count
        sector_median
        ratio
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

const ThreatPulseBenchmarkContent = ({ period }: { period: PulsePeriodValue }) => {
  const theme = useTheme<Theme>();
  const { t_i18n, n } = useFormatter();
  const { translateEntityType } = useEntityTranslation();
  const { pulseBenchmark } = useLazyLoadQuery<ThreatPulseBenchmarkQuery>(threatPulseBenchmarkQuery, { period }, { fetchPolicy: 'store-and-network' });
  const secondary = { color: theme.palette.text.secondary };
  const locked = pulseBenchmark.unavailable_reason === 'contribution_required';
  useThreatPulseImpression('benchmark_template', locked);
  if (locked) {
    // The template stays discoverable in preview: each tile names what it would show once the platform contributes.
    return (
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }} data-testid="threat-pulse-benchmark-locked">
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <ThreatPulsePreviewChip />
          <Text variant="content-compact" style={secondary}>
            {t_i18n('Sector benchmarks compare the activity of this platform with the median of its sector, without revealing any other platform.')}
          </Text>
        </Box>
        <ThreatPulseLockedRow label={t_i18n('This platform against the median of its sector, by type and activity')} />
        <ThreatPulseLockedRow label={t_i18n('Objects this platform reports well above its sector')} />
        <ThreatPulseLockedRow label={t_i18n('Contributing platforms of the sector')} />
        <Box sx={{ display: 'flex', justifyContent: 'flex-start', paddingTop: 0.5 }}>
          <ThreatPulseUnlockCta surface="benchmark_template" />
        </Box>
      </Box>
    );
  }
  if (!pulseBenchmark.readable) {
    return (
      <Text variant="content-compact" style={secondary} data-testid="threat-pulse-benchmark-unavailable">
        {t_i18n(PULSE_UNAVAILABLE_MESSAGES[pulseBenchmark.unavailable_reason ?? 'not_enabled'] ?? 'Threat Pulse is not enabled on this platform.')}
      </Text>
    );
  }
  const header = (label: string) => <th><Text variant="content-compact" style={secondary}>{label}</Text></th>;
  const median = (value: number | null | undefined) => (value !== null && value !== undefined
    ? <Text variant="content-compact">{n(value)}</Text>
    : <Text variant="content-compact" style={secondary}>{t_i18n('Not published')}</Text>);
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }} data-testid="threat-pulse-benchmark">
      <Text variant="content-compact" style={secondary}>
        {t_i18n('Sector: {sector} - {platforms}', {
          values: {
            sector: t_i18n(PULSE_SECTOR_LABELS[pulseBenchmark.sector_bucket ?? 'undisclosed'] ?? 'Undisclosed'),
            platforms: pulsePlatformsBucketLabel(t_i18n, pulseBenchmark.sector_platforms_bucket) ?? t_i18n('below the anonymity threshold'),
          },
        })}
      </Text>
      <Box component="table" sx={{ width: '100%', borderCollapse: 'collapse', '& th, & td': { textAlign: 'left', paddingY: 0.75, paddingRight: 2 } }}>
        <thead>
          <tr>
            {header(t_i18n('Entity type'))}
            {header(t_i18n('Activity'))}
            {header(t_i18n('This platform'))}
            {header(t_i18n('Sector median'))}
            {header(t_i18n('Network median'))}
            {header(t_i18n('Ratio'))}
          </tr>
        </thead>
        <tbody>
          {pulseBenchmark.metrics.map((metric) => (
            <tr key={`${metric.object_type}-${metric.event_kind}`}>
              <td><Text variant="content-compact">{translateEntityType(metric.object_type)}</Text></td>
              <td><Text variant="content-compact">{t_i18n(PULSE_EVENT_KIND_LABELS[metric.event_kind] ?? metric.event_kind)}</Text></td>
              <td><Text variant="content-compact">{n(metric.platform_count)}</Text></td>
              <td>{median(metric.sector_median)}</td>
              <td>{median(metric.network_median)}</td>
              <td>{metric.ratio !== null && metric.ratio !== undefined && <Chip label={formatPulseRatio(metric.ratio)} severity={pulseRatioSeverity(metric.ratio)} />}</td>
            </tr>
          ))}
        </tbody>
      </Box>
      {pulseBenchmark.entries.length > 0 && (
        <Box>
          <Text variant="title-xs" style={{ marginBottom: theme.spacing(1) }}>{t_i18n('Above the sector median')}</Text>
          <Box component="ul" sx={{ listStyle: 'none', margin: 0, padding: 0 }}>
            {pulseBenchmark.entries.map((entry) => {
              const link = resolveLink(entry.entity.entity_type);
              const name = <ThreatPulseEntityName name={entry.entity.representative.main} />;
              return (
                <Box component="li" key={entry.entity.id} sx={{ display: 'flex', alignItems: 'center', gap: 1.5, paddingY: 0.5 }}>
                  <ItemIcon type={entry.entity.entity_type} />
                  <Box sx={{ flex: 1, minWidth: 0 }}>
                    {link ? <Link to={`${link}/${entry.entity.id}`} style={{ color: 'inherit' }}>{name}</Link> : name}
                  </Box>
                  <Text variant="content-compact" style={secondary}>
                    {t_i18n('{count} on this platform, sector median {median}', { values: { count: n(entry.platform_count), median: n(entry.sector_median) } })}
                  </Text>
                  <Chip label={formatPulseRatio(entry.ratio)} severity={pulseRatioSeverity(entry.ratio)} />
                </Box>
              );
            })}
          </Box>
        </Box>
      )}
    </Box>
  );
};

interface ThreatPulseBenchmarkProps {
  title?: string;
  // Derived from the dashboard date range: it replaces the widget's own period selector.
  period?: PulsePeriodValue;
  popover?: ReactNode;
}

/**
 * Sector benchmark (Enterprise Edition): the activity this platform contributed versus the median of the platforms of
 * its sector bucket, published only above the anonymity threshold.
 */
const ThreatPulseBenchmark = ({ title, period: dashboardPeriod, popover }: ThreatPulseBenchmarkProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [selectedPeriod, setSelectedPeriod] = useState<PulsePeriodValue>('last_30_days');
  const period = dashboardPeriod ?? selectedPeriod;
  const action = (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
      {dashboardPeriod ? (
        <Text variant="content-compact" style={{ color: theme.palette.text.secondary }} data-testid="threat-pulse-benchmark-period">
          {t_i18n(PULSE_PERIOD_LABELS[period])}
        </Text>
      ) : (
        <Select value={period} onValueChange={(value) => setSelectedPeriod(value as PulsePeriodValue)}>
          <SelectTrigger aria-label={t_i18n('Period')} style={{ width: 140 }}>
            <SelectValue>{t_i18n(PULSE_PERIOD_LABELS[period])}</SelectValue>
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Period')}>
            {PULSE_PERIODS.map((value) => (
              <SelectItem key={value} value={value}>{t_i18n(PULSE_PERIOD_LABELS[value])}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}
      {popover}
    </Box>
  );
  return (
    <Card title={title ?? t_i18n('Sector benchmark')} action={action}>
      <Suspense fallback={<Spinner label={t_i18n('Loading')} />}>
        <ThreatPulseBenchmarkContent period={period} />
      </Suspense>
    </Card>
  );
};

export default ThreatPulseBenchmark;
