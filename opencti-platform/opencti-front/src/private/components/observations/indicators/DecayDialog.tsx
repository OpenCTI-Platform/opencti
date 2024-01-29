import React, { FunctionComponent } from 'react';
import DialogContent from '@mui/material/DialogContent';
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
import moment from 'moment-timezone';
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
  const { t_i18n } = useFormatter();

  const indicatorDecayDetails = indicator.decayLiveDetails;

  const decayHistory = indicator.decay_history ? [...indicator.decay_history] : [];
  const decayLivePoints = indicatorDecayDetails?.live_points ? [...indicatorDecayDetails.live_points] : [];

  const getScoreLabelFor = (score: number) => {
    if (score === indicator.decay_base_score) {
      return 'Score at creation';
    } if (score === indicator.x_opencti_score) {
      return 'Current stable score';
    } if (score === indicator.decay_applied_rule?.decay_revoke_score) {
      return 'Revoke score';
    }
    return 'Stability threshold';
  };

  const getStyleFor = (score: number) => {
    if (score === indicator.x_opencti_score) {
      return {
        color: theme.palette.success.main,
        fontWeight: 'bold',
      };
    } if (score === indicator.decay_applied_rule?.decay_revoke_score) {
      return { color: theme.palette.secondary.main };
    }
    return { color: theme.palette.text.primary };
  };

  const getDateAsTextFor = (history: LabelledDecayHistory) => {
    console.log('getDateAsTextFor history:', history);
    if (indicator.x_opencti_score === null || indicator.x_opencti_score === undefined) {
      return 'N/A';
    } if (history.score < indicator.x_opencti_score) {
      return moment(history.updated_at).fromNow();
    }
    return moment(history.updated_at).format('DD MMM yyyy HH:mm A');
  };

  const decayFullHistory: LabelledDecayHistory[] = [];
  decayHistory.map((history) => (
    decayFullHistory.push({
      score: history.score,
      updated_at: history.updated_at,
      label: getScoreLabelFor(history.score),
      style: getStyleFor(history.score),
    })
  ));

  decayLivePoints.map((history) => (
    decayFullHistory.push({
      score: history.score,
      updated_at: history.updated_at,
      label: getScoreLabelFor(history.score),
      style: getStyleFor(history.score),
    })
  ));

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
                      <TableCell sx={history.style}>{getDateAsTextFor(history)}</TableCell>
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
