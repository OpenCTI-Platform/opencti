import React, { FunctionComponent } from 'react';
import DialogContent from '@mui/material/DialogContent';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import Paper from '@mui/material/Paper';
import { SxProps } from '@mui/material';
import { Theme } from '@mui/material/styles/createTheme';
import { useTheme } from '@mui/styles';
import { IndicatorDetails_indicator$data } from '@components/observations/indicators/__generated__/IndicatorDetails_indicator.graphql';
import { useFormatter } from '../../../../components/i18n';

interface DecayDialogContentProps {
  indicator: IndicatorDetails_indicator$data,
}

export interface LabelledDecayHistory {
  updated_at: Date
  score: number
  label: string
  style: SxProps<Theme>
}

const DecayDialogContent : FunctionComponent<DecayDialogContentProps> = ({ indicator }) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fldt } = useFormatter();

  const indicatorDecayDetails = indicator.decayLiveDetails;

  const decayHistory = indicator.x_opencti_decay_history ? [...indicator.x_opencti_decay_history] : [];
  const decayLivePoints = indicatorDecayDetails?.live_points ? [...indicatorDecayDetails.live_points] : [];
  const decayReactionPoints = indicator.x_opencti_decay_rule?.decay_points ?? [];

  const currentScoreLineStyle = {
    color: theme.palette.success.main,
    fontWeight: 'bold',
  };
  const revokeScoreLineStyle = {
    color: theme.palette.error.main,
  };
  const decayFullHistory: LabelledDecayHistory[] = [];
  decayHistory.map((history, index) => (
    decayFullHistory.push({
      score: history.score,
      updated_at: history.updated_at,
      label: index === 0 ? 'Score at creation' : 'Score updated',
      style: index === decayHistory.length - 1 ? currentScoreLineStyle : {},
    })
  ));

  decayLivePoints.map((history, index) => (
    decayFullHistory.push({
      score: history.score,
      updated_at: history.updated_at,
      label: index === decayLivePoints.length - 1 ? 'Revoke score' : 'Score update planned',
      style: index === decayLivePoints.length - 1 ? revokeScoreLineStyle : {},
    })
  ));

  if (indicatorDecayDetails && indicatorDecayDetails.live_score && indicatorDecayDetails.live_score !== indicator.x_opencti_score) {
    decayFullHistory.push({
      score: indicatorDecayDetails.live_score,
      updated_at: new Date(),
      label: 'Current live score',
      style: currentScoreLineStyle,
    });
  }

  decayFullHistory.sort((a, b) => {
    return new Date(a.updated_at).getTime() - new Date(b.updated_at).getTime();
  });

  return (
    <DialogContent>
      <Grid
        container={true}
        spacing={3}
        style={{ borderColor: 'white', borderWidth: 1 }}
      >
        <Grid item={true} xs={8}>
          <Typography variant="h6">
            {t_i18n('Lifecycle key information')}
          </Typography>
          <TableContainer component={Paper}>
            <Table sx={{ maxHeight: 440 }} size="small" aria-label="lifecycle history">
              <TableHead>
                <TableRow>
                  <TableCell>{t_i18n('Information')}</TableCell>
                  <TableCell>{t_i18n('Score')}</TableCell>
                  <TableCell>{t_i18n('Date')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {decayFullHistory.map((history, index) => {
                  return (
                    <TableRow key={index}>
                      <TableCell sx={history.style}>{t_i18n(history.label)}</TableCell>
                      <TableCell sx={history.style}>{history.score}</TableCell>
                      <TableCell sx={history.style}>{fldt(history.updated_at)}</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableContainer>
        </Grid>
        <Grid item={true} xs={4}>
          <Typography variant="h6">
            {t_i18n('Applied decay rule')}
          </Typography>
          <ul>
            <li>{t_i18n('Base score:')} { indicator.x_opencti_base_score }</li>
            <li>{t_i18n('Lifetime (in days):')} { indicator.x_opencti_decay_rule?.decay_lifetime ?? 'Not set'}</li>
            <li>{t_i18n('Pound factor:')} { indicator.x_opencti_decay_rule?.decay_pound ?? 'Not set'}</li>
            <li>{t_i18n('Revoke score:')} { indicator.x_opencti_decay_rule?.decay_revoke_score ?? 'Not set'}</li>
            <li>{t_i18n('Reaction points:')} {decayReactionPoints.join(', ')}</li>
          </ul>
        </Grid>
      </Grid>
    </DialogContent>
  );
};

export default DecayDialogContent;
