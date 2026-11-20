import React from 'react';
import Box from '@mui/material/Box';
import Grid from '@mui/material/Grid';
import Stack from '@mui/material/Stack';
import Card from '@common/card/Card';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../../../components/i18n';
import { OaevLogo } from '../../../../../../static/images/logo_oaev';
import useXtmCounterpart from '../core/useXtmCounterparts';

interface OpenAevAlertCardProps {
  // The incident or sighting: the server reads its external reference URLs under the caller's
  // rights, and an alert an OpenAEV collector matched is known there by the same link.
  objectId: string | null | undefined;
  // In an overview grid: the card takes a full-width row of its own, and no empty cell is left
  // when it draws nothing.
  gridRow?: boolean;
}

/**
 * Overview card "In OpenAEV" of an incident or a sighting: the simulation inject whose detection
 * or prevention expectation an alert of this incident answered, with "Investigate in OpenAEV".
 * Most incidents never come from a simulation, so nothing is drawn without a match, while loading,
 * when OpenAEV is unavailable or not connected: no muted line and no call to action on every
 * incident of the platform.
 */
const OpenAevAlertCard: React.FC<OpenAevAlertCardProps> = ({ objectId, gridRow = false }) => {
  const { t_i18n } = useFormatter();
  const state = useXtmCounterpart('openaev', objectId);
  if (state.status !== 'match') return null;
  const { counterpart } = state;

  const card = (
    <Card title={t_i18n('In OpenAEV')}>
      <Stack direction="row" spacing={1.5} sx={{ alignItems: 'center' }} data-testid="openaev-alert-card">
        <Box aria-hidden sx={{ display: 'inline-flex', flexShrink: 0, '& svg': { width: 24, height: 24 } }}>
          <OaevLogo />
        </Box>
        <Box sx={{ minWidth: 0, flexGrow: 1 }}>
          <Box
            title={counterpart.object_name ?? undefined}
            sx={{ typography: 'body2', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
          >
            {counterpart.object_name ?? t_i18n('Simulation inject')}
          </Box>
          <Box
            title={counterpart.key}
            sx={{ typography: 'caption', color: 'text.secondary', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
          >
            {`${t_i18n('Alert expected by this inject')}: ${counterpart.key}`}
          </Box>
        </Box>
        <Button
          variant="secondary"
          size="small"
          href={counterpart.object_url}
          target="_blank"
          rel="noopener noreferrer"
        >
          {t_i18n('Investigate in OpenAEV')}
        </Button>
      </Stack>
    </Card>
  );
  return gridRow ? <Grid size={12}>{card}</Grid> : card;
};

export default OpenAevAlertCard;
