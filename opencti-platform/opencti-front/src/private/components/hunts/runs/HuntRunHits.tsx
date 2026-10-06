import React, { useState } from 'react';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import { useTheme } from '@mui/styles';
import { Chip, Text, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Button from '@common/button/Button';
import Card from '../../../../components/common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { HuntLearnMore } from '../HuntLearnMore';
import { HUNT_DOCS, huntHitRecurrence, huntRunHitsBreakdown } from '../hunt-utils';
import useHuntConfiguration from '../useHuntConfiguration';

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
  hitsCount?: number | null;
  newCount?: number | null;
  recurringCount?: number | null;
  identified?: boolean | null;
  windowContinued: boolean;
  platform: string;
  hits: ReadonlyArray<HuntRunHit>;
}

/** A value that may be cut by its column, readable whole in its tooltip. */
const Cut = ({ value, full }: { value: string; full?: string }) => (
  <Tooltip>
    <TooltipTrigger asChild>
      <span tabIndex={0} style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{value}</span>
    </TooltipTrigger>
    <TooltipContent>{full ?? value}</TooltipContent>
  </Tooltip>
);

/**
 * The hits of a run: how many, how many were never seen before for the hunt on this platform, the window the run
 * searched, then each sampled hit with what it involved and whether it is new or since when the hunt knows it.
 */
const HuntRunHits = ({ hitsCount, newCount, recurringCount, identified, windowContinued, platform, hits }: HuntRunHitsProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, n, fldt, fsd, mhd } = useFormatter();
  const { scheduleLookbackMinutes } = useHuntConfiguration();
  const [showAll, setShowAll] = useState(false);
  const breakdown = huntRunHitsBreakdown({ hits_count: hitsCount, hits_new_count: newCount, hits_recurring_count: recurringCount, hits_identified: identified }, t_i18n, n);
  const shown = showAll ? hits : hits.slice(0, HITS_SHOWN);
  const caption = { display: 'block', marginTop: theme.spacing(0.5) };
  return (
    <Card title={t_i18n('Hits')} action={<HuntLearnMore href={HUNT_DOCS.hitCounting} />}>
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
          <TableContainer style={{ marginTop: theme.spacing(1.5) }}>
            <Table size="small" aria-label={t_i18n('Hits')} data-testid="hunt-run-hits" style={{ tableLayout: 'fixed' }}>
              <TableHead>
                <TableRow>
                  <TableCell style={{ width: '20%' }}>{t_i18n('Time')}</TableCell>
                  <TableCell style={{ width: '22%' }}>{t_i18n('Host and user')}</TableCell>
                  <TableCell>{t_i18n('Matched')}</TableCell>
                  <TableCell style={{ width: '30%' }} align="right">{t_i18n('History')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {shown.map((hit, index) => {
                  const recurrence = huntHitRecurrence(hit, t_i18n, n, fsd);
                  const where = [hit.host, hit.user].filter((value): value is string => !!value).join(' / ');
                  const [first] = hit.matched;
                  const matched = first ? `${first.field}${first.value_preview ? ` = ${first.value_preview}` : ''}` : (hit.process ?? '');
                  return (
                    <TableRow key={`${hit.event_id ?? ''}-${hit.timestamp ?? ''}-${index}`}>
                      <TableCell>{hit.timestamp ? <Cut value={mhd(hit.timestamp)} full={fldt(hit.timestamp)} /> : t_i18n('Undated')}</TableCell>
                      <TableCell>{where ? <Cut value={where} /> : '-'}</TableCell>
                      <TableCell>{matched ? <Cut value={matched} /> : '-'}</TableCell>
                      <TableCell align="right">
                        {recurrence && !recurrence.isNew && hit.known_since && (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              {/* rounded-sm is the radius of the chip, so the focus ring follows its shape */}
                              <span
                                tabIndex={0}
                                className="inline-flex rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-filigran-brand-primary focus-visible:ring-offset-2 focus-visible:ring-offset-focus"
                                data-testid="hunt-run-hit-recurrence-trigger"
                              >
                                <Chip label={recurrence.label} severity="neutral" data-testid="hunt-run-hit-recurrence" />
                              </span>
                            </TooltipTrigger>
                            <TooltipContent>{t_i18n('First found {date}', { values: { date: fldt(hit.known_since) } })}</TooltipContent>
                          </Tooltip>
                        )}
                        {recurrence?.isNew && <Chip label={recurrence.label} severity="info" data-testid="hunt-run-hit-recurrence" />}
                        {!recurrence && <Text variant="content-caption" as="span">-</Text>}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableContainer>
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
