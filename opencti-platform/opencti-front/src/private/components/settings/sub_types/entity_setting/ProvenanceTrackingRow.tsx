import React from 'react';
import { graphql } from 'react-relay';
import Box from '@mui/material/Box';
// FDS-WORKAROUND #63: the design system ships no skeleton; replace with it once it does.
import Skeleton from '@mui/material/Skeleton';
import { Chip, Switch, Text, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../../components/i18n';

export const provenanceTrackingRowStatisticsQuery = graphql`
  query ProvenanceTrackingRowStatisticsQuery($types: [String!]!) {
    provenanceTypeStatistics(types: $types) {
      entity_type
      with_provenance
      corroborated
      last_asserted_at
    }
  }
`;

export const PROVENANCE_DOCUMENTATION = 'https://docs.opencti.io/latest/usage/provenance/';
export const PROVENANCE_RELATIONSHIP_TYPES_DOCUMENTATION = `${PROVENANCE_DOCUMENTATION}#relationship-types`;

export interface ProvenanceTypeStatistics {
  readonly with_provenance: number;
  readonly corroborated: number;
  readonly last_asserted_at?: string | null;
}

/**
 * Statistics of the concrete types an abstract type stands for, as one: the sums, and the latest assertion.
 */
export const sumProvenanceStatistics = (entries: ReadonlyArray<ProvenanceTypeStatistics>): ProvenanceTypeStatistics | null => {
  if (entries.length === 0) {
    return null;
  }
  const lastAssertedAt = entries
    .map((entry) => entry.last_asserted_at)
    .filter((date): date is string => !!date)
    .sort()
    .at(-1) ?? null;
  return {
    with_provenance: entries.reduce((total, entry) => total + entry.with_provenance, 0),
    corroborated: entries.reduce((total, entry) => total + entry.corroborated, 0),
    last_asserted_at: lastAssertedAt,
  };
};

// Label, assertions, last assertion and switch, shared by the rows and the header of a list
export const PROVENANCE_TRACKING_COLUMNS = 'minmax(0, 1.3fr) minmax(0, 1.2fr) minmax(0, 0.8fr) auto';

export const provenanceTrackingRowSx = {
  display: 'grid',
  gridTemplateColumns: PROVENANCE_TRACKING_COLUMNS,
  alignItems: 'center',
  columnGap: 2,
  minHeight: 36,
  px: 1,
};

const truncateSx = { minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' };

interface ProvenanceTrackingRowProps {
  label: string;
  // Accessible name of the switch
  switchLabel: string;
  tracked: boolean;
  onTrackedChange: (tracked: boolean) => void;
  // undefined while the statistics load, null when no element of the type has a source
  statistics: ProvenanceTypeStatistics | null | undefined;
  recommended?: boolean;
  disabled?: boolean;
  // A row on its own, without the column headers of a list
  standalone?: boolean;
}

/**
 * One type of the provenance configuration: its tracking switch next to how much of its knowledge has sources.
 */
const ProvenanceTrackingRow = ({
  label,
  switchLabel,
  tracked,
  onTrackedChange,
  statistics,
  recommended = false,
  disabled = false,
  standalone = false,
}: ProvenanceTrackingRowProps) => {
  const { t_i18n, n, rd, fldt } = useFormatter();
  let assertions: React.ReactNode;
  let lastAssertion: React.ReactNode = null;
  if (statistics === undefined) {
    assertions = <Skeleton variant="text" width={standalone ? 160 : '70%'} aria-label={t_i18n('Loading')} />;
    lastAssertion = <Skeleton variant="text" width={standalone ? 120 : '50%'} />;
  } else if (!statistics || statistics.with_provenance === 0) {
    assertions = <Text variant="content-caption" as="span">{t_i18n('No assertion yet')}</Text>;
  } else {
    assertions = (
      <Box sx={truncateSx}>
        <Text variant="content-compact" as="span">
          {t_i18n('{count} with sources', { values: { count: n(statistics.with_provenance) } })}
        </Text>
        <Text variant="content-caption" as="span">
          {` - ${t_i18n('{count} corroborated', { values: { count: n(statistics.corroborated) } })}`}
        </Text>
      </Box>
    );
    if (statistics.last_asserted_at) {
      const relative = rd(statistics.last_asserted_at);
      lastAssertion = (
        <Tooltip>
          <TooltipTrigger asChild>
            <Box component="time" dateTime={statistics.last_asserted_at} sx={truncateSx}>
              <Text variant="content-compact" as="span">
                {standalone ? t_i18n('Last asserted {date}', { values: { date: relative } }) : relative}
              </Text>
            </Box>
          </TooltipTrigger>
          <TooltipContent>{fldt(statistics.last_asserted_at)}</TooltipContent>
        </Tooltip>
      );
    }
  }
  const trackingSwitch = <Switch checked={tracked} disabled={disabled} aria-label={switchLabel} onCheckedChange={onTrackedChange} />;
  if (standalone) {
    // The label of a single type is a sentence: it takes the first line, its statistics the second
    return (
      <Box role="row" data-testid="provenance-tracking-row" sx={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) auto', alignItems: 'center', columnGap: 2, rowGap: 0.5 }}>
        <Box role="cell"><Text variant="content-base" as="span">{label}</Text></Box>
        <Box role="cell" sx={{ display: 'flex', justifyContent: 'flex-end' }}>{trackingSwitch}</Box>
        <Box role="cell" sx={{ display: 'flex', gap: 2, minWidth: 0, gridColumn: '1 / -1' }}>
          {assertions}
          {lastAssertion}
        </Box>
      </Box>
    );
  }
  return (
    <Box
      role="row"
      data-testid="provenance-tracking-row"
      sx={{
        ...provenanceTrackingRowSx,
        borderBottom: '1px solid var(--border-elevation-subtle)',
        '&:hover': { background: 'var(--bg-elevation-hover)' },
      }}
    >
      <Box role="cell" sx={{ display: 'flex', alignItems: 'center', gap: 1, minWidth: 0 }}>
        <Box sx={truncateSx}>
          <Text variant="content-compact-medium" as="span">{label}</Text>
        </Box>
        {recommended && <Chip label={t_i18n('Recommended')} severity="info" />}
      </Box>
      <Box role="cell" sx={{ minWidth: 0 }}>{assertions}</Box>
      <Box role="cell" sx={{ minWidth: 0 }}>{lastAssertion}</Box>
      <Box role="cell" sx={{ display: 'flex', justifyContent: 'flex-end' }}>{trackingSwitch}</Box>
    </Box>
  );
};

export default ProvenanceTrackingRow;
