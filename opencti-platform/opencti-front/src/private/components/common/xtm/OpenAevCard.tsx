import React from 'react';
import Box from '@mui/material/Box';
import Grid from '@mui/material/Grid';
import Stack from '@mui/material/Stack';
import Card from '@common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import { OaevLogo } from '../../../../static/images/logo_oaev';
import useXtmCounterpart, { normaliseXtmKey, XtmCounterpartKind } from './useXtmCounterparts';

interface OpenAevCardProps {
  kind: XtmCounterpartKind;
  // The natural key both platforms share: hostname, MITRE id, CVE id or STIX id.
  counterpartKey: string | null | undefined;
  // In an overview grid: the card takes a full-width row of its own, and no empty cell is left
  // when it draws nothing.
  gridRow?: boolean;
}

type CounterpartFact = { key: string; value: string };
type Translate = (message: string, options?: { values: Record<string, number> }) => string;

// The facts OpenAEV computes (LocalObjectService): counts and the start of the latest simulation.
// An unknown key or a value that is not a number is not shown.
const COUNT_FACTS: Record<string, string> = {
  findings: '{count, plural, one {# finding} other {# findings}}',
  affected_assets: '{count, plural, one {# affected asset} other {# affected assets}}',
  simulations: '{count, plural, one {# simulation} other {# simulations}}',
};

export const formatCounterpartFacts = (
  facts: ReadonlyArray<CounterpartFact> | null | undefined,
  t_i18n: Translate,
  formatDate: (date: string) => string,
): string[] => {
  const out: string[] = [];
  for (const fact of facts ?? []) {
    const message = COUNT_FACTS[fact.key];
    if (message) {
      const count = Number(fact.value);
      if (Number.isInteger(count) && count >= 0) out.push(t_i18n(message, { values: { count } }));
    } else if (fact.key === 'last_simulation' && !Number.isNaN(Date.parse(fact.value))) {
      out.push(`${t_i18n('Last simulation')}: ${formatDate(fact.value)}`);
    }
  }
  return out;
};

// The overview widget the card follows: the later of Details and Basic information in the page's
// layout, so the card takes the full-width row right under them, above the lists and Notes, which
// stays the last section of every overview. Null when the layout shows neither (the card then
// closes the grid).
export const openAevCardAnchorKey = (layout: ReadonlyArray<{ key: string }>): string | null => {
  let anchor: string | null = null;
  for (const { key } of layout) {
    if (key === 'details' || key === 'basicInformation') anchor = key;
  }
  return anchor;
};

/**
 * Overview card "In OpenAEV": on a match, the OpenAEV counterpart with the identifier both
 * platforms share and its key facts (findings, affected assets, simulations and the latest one);
 * without a match, a muted "Not in OpenAEV" line. The card is informational: the hero pivot of the
 * same page is the single "Open in OpenAEV" action, so the card carries no link of its own. Nothing
 * is drawn while loading or when OpenAEV is not connected: the hero action carries the "Connect
 * OpenAEV" call to action, so the overview does not repeat it. A threat is matched on its STIX id,
 * which means nothing to an analyst: its name identifies it, so no shared identifier line is shown.
 */
const OpenAevCard: React.FC<OpenAevCardProps> = ({ kind, counterpartKey, gridRow = false }) => {
  const { t_i18n, fd } = useFormatter();
  const state = useXtmCounterpart('openaev', kind, counterpartKey);
  if (state.status !== 'match' && state.status !== 'no_match') return null;
  const sharedKey = kind === 'THREAT' ? null : normaliseXtmKey(kind, counterpartKey);
  const match = state.status === 'match' ? state.counterpart : null;
  const facts = match ? formatCounterpartFacts(match.facts, t_i18n, fd) : [];

  const card = (
    <Card title={t_i18n('In OpenAEV')}>
      <Stack direction="row" spacing={1.5} sx={{ alignItems: 'center' }} data-testid="openaev-card">
        <Box
          aria-hidden
          sx={{
            display: 'inline-flex',
            flexShrink: 0,
            opacity: match ? 1 : 0.5,
            '& svg': { width: 24, height: 24 },
          }}
        >
          <OaevLogo />
        </Box>
        <Box sx={{ minWidth: 0 }}>
          <Box
            title={match?.object_name ?? undefined}
            sx={{ typography: 'body2', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
          >
            {match ? (match.object_name ?? t_i18n('Open in OpenAEV')) : t_i18n('Not in OpenAEV')}
          </Box>
          {sharedKey && (
            <Box sx={{ typography: 'caption', color: 'text.secondary' }}>
              {`${t_i18n('Shared identifier')}: ${sharedKey}`}
            </Box>
          )}
          {facts.length > 0 && (
            <Box sx={{ typography: 'caption', color: 'text.secondary' }} data-testid="openaev-card-facts">
              {facts.join(' · ')}
            </Box>
          )}
        </Box>
      </Stack>
    </Card>
  );
  return gridRow ? <Grid size={12}>{card}</Grid> : card;
};

export default OpenAevCard;
