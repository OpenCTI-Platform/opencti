import React from 'react';
import Box from '@mui/material/Box';
import Grid from '@mui/material/Grid';
import Stack from '@mui/material/Stack';
import Card from '@common/card/Card';
import Button from '@common/button/Button';
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

/**
 * Overview card "In OpenAEV": on a match, the OpenAEV counterpart with the identifier both
 * platforms share and a link to it (its simulations, findings and expectation results live
 * there); without a match, a muted "Not in OpenAEV" line. Nothing is drawn while loading or when
 * OpenAEV is not connected: the hero action of the same page carries the "Connect OpenAEV" call
 * to action, so the overview does not repeat it.
 */
const OpenAevCard: React.FC<OpenAevCardProps> = ({ kind, counterpartKey, gridRow = false }) => {
  const { t_i18n } = useFormatter();
  const state = useXtmCounterpart('openaev', kind, counterpartKey);
  if (state.status !== 'match' && state.status !== 'no_match') return null;
  const sharedKey = normaliseXtmKey(kind, counterpartKey);
  const match = state.status === 'match' ? state.counterpart : null;

  const card = (
    <Card
      title={t_i18n('In OpenAEV')}
      action={match && (
        <Button
          variant="secondary"
          size="small"
          href={match.object_url}
          target="_blank"
          rel="noopener noreferrer"
        >
          {t_i18n('Open in OpenAEV')}
        </Button>
      )}
    >
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
        </Box>
      </Stack>
    </Card>
  );
  return gridRow ? <Grid size={12}>{card}</Grid> : card;
};

export default OpenAevCard;
