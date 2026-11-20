import React from 'react';
import Box from '@mui/material/Box';
import Grid from '@mui/material/Grid';
import Stack from '@mui/material/Stack';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Card from '@common/card/Card';
import { useFormatter } from '../../../../../../components/i18n';
import { OcrqLogo } from '../../../../../../static/images/logo_ocrq';
import useGranted, { SETTINGS_SETPARAMETERS } from '../../../../../../utils/hooks/useGranted';
import { useCompactPivot } from '../core/useCompactPivot';
import { XTM_CONNECT_DOC_URL } from '../core/xtmConnect';
import { withTooltip } from '../core/XtmTooltip';
import useXtmCounterpart, { sharedIdentifierOf } from '../core/useXtmCounterparts';

// The OpenCRQ side of the cross-platform pivots: same controls, states and wording as the OpenAEV
// ones (OpenAevPivot, OpenAevCard, OpenAevRowMark), the OpenCRQ mark, and the risk OpenCRQ
// quantifies for the object (the risk scenarios it drives, their annual loss expectancy and, for a
// CVE, the loss avoided by fixing it). OpenCRQ holds threats (STIX id), vulnerabilities (CVE) and
// assets (hostname); attack patterns and alerts have no OpenCRQ counterpart.

export const OPENCRQ_PRODUCT = 'opencrq';

interface OpenCrqProps {
  // The OpenCTI object: the server reads its key (hostname, CVE id or STIX id) under the caller's
  // rights; a type OpenCRQ does not hold answers not_supported and nothing is drawn.
  objectId: string | null | undefined;
}

type CounterpartFact = { key: string; value: string };
type Translate = (message: string, options?: { values: Record<string, number> }) => string;

// Amounts are whole units of the OpenCRQ tenant's currency, shown compact (125K) as OpenAEV does.
const MONEY_FACTS: Record<string, string> = {
  annual_loss: 'Annual loss expectancy',
  fix_value: 'Loss avoided by fixing',
};

/** The facts OpenCRQ answered, known keys with a numeric value only, in display order. */
export const formatOpenCrqFacts = (
  facts: ReadonlyArray<CounterpartFact> | null | undefined,
  t_i18n: Translate,
  n: (value: number) => string,
): string[] => {
  const byKey = new Map((facts ?? []).map((f) => [f.key, Number(f.value)]));
  const out: string[] = [];
  const scenarios = byKey.get('risk_scenarios');
  if (scenarios !== undefined && Number.isInteger(scenarios) && scenarios >= 0) {
    out.push(t_i18n('{count, plural, one {# risk scenario} other {# risk scenarios}}', { values: { count: scenarios } }));
  }
  Object.entries(MONEY_FACTS).forEach(([key, label]) => {
    const value = byKey.get(key);
    if (value !== undefined && Number.isFinite(value) && value >= 0) out.push(`${t_i18n(label)}: ${n(value)}`);
  });
  return out;
};

/**
 * Hero action of an object OpenCRQ can also hold, beside "Open in OpenAEV": "Open in OpenCRQ" on a
 * match, a disabled "Not in OpenCRQ" without one, a disabled muted "OpenCRQ is unavailable" when
 * OpenCRQ could not answer this time, and "Connect OpenCRQ" when OpenCRQ is not connected
 * (disabled, with a read-only hint, for a user who cannot configure the platform). Silent while
 * loading and when there is nothing to match. Below 1280 px the same states render as the framed
 * icon button.
 */
export const OpenCrqPivot: React.FC<OpenCrqProps> = ({ objectId }) => {
  const { t_i18n } = useFormatter();
  const canConfigure = useGranted([SETTINGS_SETPARAMETERS]);
  const state = useXtmCounterpart(OPENCRQ_PRODUCT, objectId);
  const compact = useCompactPivot();

  let label: string;
  let tooltip: string;
  let href: string | undefined;
  let disabled = false;
  switch (state.status) {
    case 'match':
      label = t_i18n('Open in OpenCRQ');
      tooltip = state.counterpart.object_name ? `${label}: ${state.counterpart.object_name}` : label;
      href = state.counterpart.object_url;
      break;
    case 'no_match':
      label = t_i18n('Not in OpenCRQ');
      tooltip = label;
      disabled = true;
      break;
    case 'unavailable':
      label = t_i18n('OpenCRQ is unavailable');
      tooltip = label;
      disabled = true;
      break;
    case 'not_connected':
      label = t_i18n('Connect OpenCRQ');
      if (canConfigure) {
        tooltip = t_i18n('Connect OpenCRQ to pivot to this object and see the risk it drives');
        href = XTM_CONNECT_DOC_URL;
      } else {
        tooltip = t_i18n('OpenCRQ is not connected: ask an administrator to connect it');
        disabled = true;
      }
      break;
    default:
      return null;
  }
  const ariaLabel = state.status === 'not_connected' && disabled ? t_i18n('OpenCRQ is not connected') : label;
  const link = href ? { href, target: '_blank', rel: 'noopener noreferrer' } : {};

  if (compact) {
    return (
      <IconButton
        variant="secondary"
        size="default"
        disabled={disabled}
        aria-label={ariaLabel}
        tooltip={tooltip}
        data-testid="opencrq-pivot"
        data-status={state.status}
        {...link}
      >
        <OcrqLogo />
      </IconButton>
    );
  }
  return withTooltip(
    tooltip,
    <Button
      variant="secondary"
      startIcon={<OcrqLogo />}
      disabled={disabled}
      aria-label={disabled ? ariaLabel : undefined}
      data-testid="opencrq-pivot"
      data-status={state.status}
      {...link}
    >
      {label}
    </Button>,
  );
};

/**
 * Overview card "In OpenCRQ": on a match, the OpenCRQ counterpart with the identifier both
 * platforms share and the risk it drives (risk scenarios, annual loss expectancy, loss avoided by
 * fixing); without a match, a muted "Not in OpenCRQ" line. Informational, no link of its own (the
 * hero pivot is the single action). Nothing while loading, when OpenCRQ is not connected or
 * unavailable (the hero carries them), or when there is nothing to match. A threat is matched on
 * its STIX id: no shared identifier line.
 */
export const OpenCrqCard: React.FC<OpenCrqProps & { gridRow?: boolean }> = ({ objectId, gridRow = false }) => {
  const { t_i18n, n } = useFormatter();
  const state = useXtmCounterpart(OPENCRQ_PRODUCT, objectId);
  if (state.status !== 'match' && state.status !== 'no_match') return null;
  const match = state.status === 'match' ? state.counterpart : null;
  const sharedKey = sharedIdentifierOf(match);
  const facts = match ? formatOpenCrqFacts(match.facts, t_i18n, n) : [];

  const card = (
    <Card title={t_i18n('In OpenCRQ')}>
      <Stack direction="row" spacing={1.5} sx={{ alignItems: 'center' }} data-testid="opencrq-card">
        <Box aria-hidden sx={{ display: 'inline-flex', flexShrink: 0, opacity: match ? 1 : 0.5, '& svg': { width: 24, height: 24 } }}>
          <OcrqLogo />
        </Box>
        <Box sx={{ minWidth: 0 }}>
          <Box
            title={match?.object_name ?? undefined}
            sx={{ typography: 'body2', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
          >
            {match ? (match.object_name ?? t_i18n('Open in OpenCRQ')) : t_i18n('Not in OpenCRQ')}
          </Box>
          {sharedKey && (
            <Box sx={{ typography: 'caption', color: 'text.secondary' }}>
              {`${t_i18n('Shared identifier')}: ${sharedKey}`}
            </Box>
          )}
          {facts.length > 0 && (
            <Box sx={{ typography: 'caption', color: 'text.secondary' }} data-testid="opencrq-card-facts">
              {facts.join(' · ')}
            </Box>
          )}
        </Box>
      </Stack>
    </Card>
  );
  return gridRow ? <Grid size={12}>{card}</Grid> : card;
};

/**
 * List-row mark of an object OpenCRQ also holds: a small OpenCRQ mark linking to the counterpart.
 * Nothing while loading, without a match, when OpenCRQ is unavailable or not connected (the hero
 * carries the CTA). The lookups of every row go out in the same batched query as the OpenAEV ones.
 */
export const OpenCrqRowMark: React.FC<OpenCrqProps> = ({ objectId }) => {
  const { t_i18n } = useFormatter();
  const state = useXtmCounterpart(OPENCRQ_PRODUCT, objectId);
  if (state.status !== 'match') return null;
  const { object_name, object_url } = state.counterpart;
  const label = object_name ? `${t_i18n('Open in OpenCRQ')}: ${object_name}` : t_i18n('Open in OpenCRQ');
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Box
          component="a"
          href={object_url}
          target="_blank"
          rel="noopener noreferrer"
          aria-label={t_i18n('Open in OpenCRQ')}
          // The row is itself a link: the mark opens OpenCRQ without opening the row.
          onClick={(event: React.MouseEvent) => event.stopPropagation()}
          data-testid="opencrq-row-mark"
          sx={{
            display: 'inline-flex',
            alignItems: 'center',
            flexShrink: 0,
            ml: 0.5,
            verticalAlign: 'middle',
            '& svg': { width: 16, height: 16 },
          }}
        >
          <OcrqLogo />
        </Box>
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  );
};
