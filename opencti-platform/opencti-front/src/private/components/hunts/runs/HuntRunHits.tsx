import React, { useState } from 'react';
import { useTheme } from '@mui/styles';
import { Chip, Text, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Button from '@common/button/Button';
import Card from '../../../../components/common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { HuntLearnMore } from '../HuntLearnMore';
import { HUNT_DOCS, huntHitRecurrence, huntRunHitsBreakdown } from '../hunt-utils';
import useHuntConfiguration from '../useHuntConfiguration';
import HuntRunTable, { HuntRunDateCell, HuntRunSortValue, huntRunTextCell, sortHuntRunRows, useHuntRunTableSort } from './HuntRunTable';

const HITS_SHOWN = 10;

export interface HuntRunHit {
  readonly event_id?: string | null;
  readonly timestamp?: string | null;
  readonly host?: string | null;
  readonly user?: string | null;
  readonly process?: string | null;
  readonly matched: ReadonlyArray<{ readonly field: string; readonly value_preview?: string | null }>;
  readonly is_new?: boolean | null;
  readonly times_seen?: number | null;
  readonly known_since?: string | null;
}

export interface HuntRunHitsProps {
  runId: string;
  hitsCount?: number | null;
  newCount?: number | null;
  recurringCount?: number | null;
  identified?: boolean | null;
  windowContinued: boolean;
  platform: string;
  hits: ReadonlyArray<HuntRunHit>;
}

interface HitRow {
  id: string;
  hit: HuntRunHit;
  time: number | null;
  field: string;
  // Without a matched value, what the hit involved is its process
  value: string;
}

const HIT_SORT_VALUES: Record<string, (row: HitRow) => HuntRunSortValue> = {
  timestamp: (row) => row.time,
  host: (row) => row.hit.host,
  user: (row) => row.hit.user,
  matched_field: (row) => row.field,
  matched_value: (row) => row.value,
};

const hitRows = (hits: ReadonlyArray<HuntRunHit>): HitRow[] => hits.map((hit, index) => {
  const [first] = hit.matched;
  return {
    id: `${hit.event_id ?? ''}-${hit.timestamp ?? ''}-${index}`,
    hit,
    time: hit.timestamp ? new Date(hit.timestamp).getTime() : null,
    field: first?.field ?? '',
    value: first ? (first.value_preview ?? '') : (hit.process ?? ''),
  };
});

/**
 * The hits of a run: how many, how many were never seen before for the hunt on this platform, the window the run
 * searched, then each sampled hit with what it involved and whether it is new or since when the hunt knows it.
 */
const HuntRunHits = ({ runId, hitsCount, newCount, recurringCount, identified, windowContinued, platform, hits }: HuntRunHitsProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, n, fldt, fsd } = useFormatter();
  const { scheduleLookbackMinutes } = useHuntConfiguration();
  const [showAll, setShowAll] = useState(false);
  const sort = useHuntRunTableSort(`hunt-run-${runId}-hits`, { sortBy: 'timestamp', orderAsc: false });
  const breakdown = huntRunHitsBreakdown({ hits_count: hitsCount, hits_new_count: newCount, hits_recurring_count: recurringCount, hits_identified: identified }, t_i18n, n);
  const sorted = sortHuntRunRows(hitRows(hits), sort.sortBy ? HIT_SORT_VALUES[sort.sortBy] : undefined, sort.orderAsc);
  const shown = showAll ? sorted : sorted.slice(0, HITS_SHOWN);
  const caption = { display: 'block', marginTop: theme.spacing(0.5) };
  const sampled = hits.length > 0 && (hitsCount ?? 0) > hits.length;
  return (
    <Card
      title={t_i18n('Hits')}
      titleAlignItems="flex-start"
      action={(
        <>
          {sampled && (
            <Text variant="content-caption" style={{ color: theme.palette.text.secondary }} data-testid="hunt-run-hits-sampled">
              {t_i18n('{shown} of {count} hits are kept as a sample, at least one per value or rule and host: counts and dates cover every hit', { values: { shown: n(hits.length), count: n(hitsCount ?? 0) } })}
            </Text>
          )}
          <HuntLearnMore href={HUNT_DOCS.hitCounting} />
        </>
      )}
    >
      <Text variant="content-compact" data-testid="hunt-run-hits-breakdown">
        {breakdown ?? ((hitsCount ?? 0) === 1 ? t_i18n('1 hit') : t_i18n('{count} hits', { values: { count: n(hitsCount ?? 0) } }))}
      </Text>
      {identified !== true && (hitsCount ?? 0) > 0 && (
        <Text variant="content-caption" style={caption} data-testid="hunt-run-hits-unidentified">
          {t_i18n('The connector does not identify single hits: every hit of this run counts as new')}
        </Text>
      )}
      {windowContinued && (
        <Text variant="content-caption" style={caption} data-testid="hunt-run-window-continued">
          {t_i18n('Searched since the previous run on {platform}, with a {minutes}-minute overlap', { values: { platform, minutes: n(scheduleLookbackMinutes) } })}
        </Text>
      )}
      {hits.length > 0 && (
        <>
          <div style={{ marginTop: theme.spacing(1.5) }}>
            <HuntRunTable
              storageKey={`hunt-run-${runId}-hits`}
              initialValues={sort.initialValues}
              onSort={sort.onSort}
              rows={shown}
              label={t_i18n('Hits')}
              testId="hunt-run-hits"
              disableNavigation
              dataColumns={{
                timestamp: {
                  id: 'timestamp',
                  label: 'Time',
                  percentWidth: 16,
                  isSortable: true,
                  render: ({ hit }: HitRow) => (hit.timestamp ? <HuntRunDateCell date={hit.timestamp} /> : t_i18n('Undated')),
                },
                host: { id: 'host', label: 'Host', percentWidth: 15, isSortable: true, render: ({ hit }: HitRow) => huntRunTextCell(hit.host) },
                user: { id: 'user', label: 'User', percentWidth: 13, isSortable: true, render: ({ hit }: HitRow) => huntRunTextCell(hit.user) },
                matched_field: { id: 'matched_field', label: 'Matched field', percentWidth: 18, isSortable: true, render: ({ field }: HitRow) => huntRunTextCell(field) },
                matched_value: { id: 'matched_value', label: 'Matched value', percentWidth: 22, isSortable: true, render: ({ value }: HitRow) => huntRunTextCell(value) },
                history: {
                  id: 'history',
                  label: 'History',
                  percentWidth: 16,
                  isSortable: false,
                  render: ({ hit }: HitRow) => {
                    const recurrence = huntHitRecurrence(hit, t_i18n, n, fsd);
                    if (recurrence?.isNew) {
                      return <Chip label={recurrence.label} severity="info" data-testid="hunt-run-hit-recurrence" />;
                    }
                    if (recurrence && hit.known_since) {
                      return (
                        <Tooltip>
                          <TooltipTrigger asChild>
                            {/* rounded-sm is the radius of the chip, so the focus ring follows its shape */}
                            <span
                              // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex
                              tabIndex={0}
                              className="inline-flex rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-filigran-brand-primary focus-visible:ring-offset-2 focus-visible:ring-offset-focus"
                              data-testid="hunt-run-hit-recurrence-trigger"
                            >
                              <Chip label={recurrence.label} severity="neutral" data-testid="hunt-run-hit-recurrence" />
                            </span>
                          </TooltipTrigger>
                          <TooltipContent>{t_i18n('First found {date}', { values: { date: fldt(hit.known_since) } })}</TooltipContent>
                        </Tooltip>
                      );
                    }
                    return '';
                  },
                },
              }}
            />
          </div>
          {hits.length > HITS_SHOWN && (
            <div style={{ marginTop: theme.spacing(1) }}>
              <Button variant="tertiary" size="small" aria-expanded={showAll} onClick={() => setShowAll(!showAll)} data-testid="hunt-run-hits-toggle">
                {showAll ? t_i18n('Show fewer hits') : t_i18n('Show the {count} sampled hits', { values: { count: n(hits.length) } })}
              </Button>
            </div>
          )}
        </>
      )}
    </Card>
  );
};

export default HuntRunHits;
