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
import DecayChart from '@components/observations/indicators/DecayChart';
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

  const decayHistory = indicator.decay_history ? [...indicator.decay_history] : [];
  const decayLivePoints = indicatorDecayDetails?.live_points ? [...indicatorDecayDetails.live_points] : [];

  const currentLiveScoreLineStyle = {
    color: theme.palette.success.main,
    fontWeight: 'bold',
  };

  const currentScoreLineStyle = {
    color: theme.palette.info.main,
    fontWeight: 'bold',
  };

  const revokeScoreLineStyle = {
    color: theme.palette.secondary.main,
  };

  const normalHistoryLineStyle = {
    color: theme.palette.text.primary,
  };

  const decayFullHistory: LabelledDecayHistory[] = [];
  decayHistory.map((history, index) => (
    decayFullHistory.push({
      score: history.score,
      updated_at: history.updated_at,
      label: index === 0 ? 'Score at creation' : 'Score updated',
      style: history.score === indicator.x_opencti_score ? currentScoreLineStyle : normalHistoryLineStyle,
    })
  ));

  decayLivePoints.map((history, index) => (
    decayFullHistory.push({
      score: history.score,
      updated_at: history.updated_at,
      label: index === decayLivePoints.length - 1 ? 'Revoke score' : 'Score update planned',
      style: index === decayLivePoints.length - 1 ? revokeScoreLineStyle : normalHistoryLineStyle,
    })
  ));

  if (indicatorDecayDetails && indicatorDecayDetails.live_score && indicatorDecayDetails.live_score !== indicator.x_opencti_score) {
    decayFullHistory.push({
      score: indicatorDecayDetails.live_score,
      updated_at: new Date(),
      label: 'Current live score',
      style: currentLiveScoreLineStyle,
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
        <Grid item={true} xs={6}>
          <DecayChart indicator={indicator}/>
        </Grid>
        <Grid item={true} xs={6}>
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

      </Grid>
    </DialogContent>
  );
};

export default DecayDialogContent;
