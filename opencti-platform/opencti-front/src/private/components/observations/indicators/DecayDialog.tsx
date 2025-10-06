import React, { FunctionComponent } from 'react';
import { SxProps } from '@mui/material';
import { Theme } from '@mui/material/styles/createTheme';
import { useTheme } from '@mui/styles';
import { IndicatorDetails_indicator$data } from '@private/components/observations/indicators/__generated__/IndicatorDetails_indicator.graphql';
import DecayChart, { DecayHistory } from '@private/components/settings/decay/DecayChart';
import { DialogContent, Grid, Paper, Table, TableBody, TableCell, TableContainer, TableHead, TableRow } from '@components';
import { useFormatter } from '../../../../components/i18n';

interface DecayDialogContentProps {
  indicator: IndicatorDetails_indicator$data,
}

export interface LabelledDecayHistory {
  updated_at: string
  score: number
  label: string
  style: SxProps<Theme>
}

const DecayDialogContent : FunctionComponent<DecayDialogContentProps> = ({ indicator }) => {
  const theme = useTheme<Theme>();
  const { t_i18n, mhd, rd } = useFormatter();

  const indicatorDecayDetails = indicator.decayLiveDetails;

  const decayHistory = indicator.decay_history ? [...indicator.decay_history] : [];
  const decayLivePoints = indicatorDecayDetails?.live_points ? [...indicatorDecayDetails.live_points] : [];

  const getDateAsTextFor = (history: DecayHistory) => {
    if (indicator.x_opencti_score === null || indicator.x_opencti_score === undefined) {
      return '-';
    } if (history.score < indicator.x_opencti_score && history.updated_at > indicator.decay_base_score_date) {
      return rd(history.updated_at);
    }
    return mhd(history.updated_at);
  };

  const getDisplayForHistory = (history: DecayHistory, index: number, currentScoreIndex: number) => {
    if (index === currentScoreIndex) {
      return {
        label: t_i18n('Current stable score'),
        style: {
          color: theme.palette.success.main,
          fontWeight: 'bold',
        },
        score: history.score,
        updated_at: getDateAsTextFor(history),
      };
    }
    if (index === 0) {
      return {
        label: t_i18n('Initial score'),
        style: { color: theme.palette.text.primary },
        score: history.score,
        updated_at: getDateAsTextFor(history),
      };
    }
    if (history.score === indicator.decay_applied_rule?.decay_revoke_score) {
      return {
        label: t_i18n('Revoke score'),
        style: { color: theme.palette.secondary.main },
        score: history.score,
        updated_at: getDateAsTextFor(history),
      };
    }
    return {
      label: t_i18n('Stable score'),
      style: { color: theme.palette.text.primary },
      score: history.score,
      updated_at: getDateAsTextFor(history),
    };
  };

  const getDisplayForUpcomingUpdates = (history: DecayHistory) => {
    if (history.score === indicator.decay_applied_rule?.decay_revoke_score) {
      return {
        label: t_i18n('Revoke score'),
        style: { color: theme.palette.secondary.main },
        score: history.score,
        updated_at: getDateAsTextFor(history),
      };
    }
    return {
      label: t_i18n('Stable score'),
      style: { color: theme.palette.text.primary },
      score: history.score,
      updated_at: getDateAsTextFor(history),
    };
  };

  const labelledHistoryList: LabelledDecayHistory[] = [];
  const currentScoreIndex = decayHistory.findLastIndex((history) => history.score === indicator.x_opencti_score);
  decayHistory.forEach((history, index) => (
    labelledHistoryList.push(getDisplayForHistory(history, index, currentScoreIndex))
  ));

  decayLivePoints.forEach((history) => (
    labelledHistoryList.push(getDisplayForUpcomingUpdates(history))
  ));

  labelledHistoryList.sort((a, b) => {
    return new Date(a.updated_at).getTime() - new Date(b.updated_at).getTime();
  });

  let chartCurvePoints: DecayHistory[] = [];
  if (indicator.decayChartData?.live_score_serie) {
    chartCurvePoints = indicator.decayChartData.live_score_serie.map((historyPoint) => historyPoint);
  }

  let chartDecayReactionPoints: number[] = [];
  if (indicator.decay_applied_rule?.decay_points) {
    chartDecayReactionPoints = indicator.decay_applied_rule?.decay_points.map((point) => point);
  }

  return (
    <DialogContent>
      <Grid
        container={true}
        spacing={3}
        style={{ borderColor: 'white', borderWidth: 1 }}
      >
        <Grid size={7}>
          <DecayChart
            currentScore={indicator.x_opencti_score || 0}
            revokeScore={indicator.decay_applied_rule?.decay_revoke_score || 0}
            reactionPoints={chartDecayReactionPoints}
            decayCurvePoint={chartCurvePoints || []}
            decayLiveScore={indicator.decayLiveDetails?.live_score}
          />
        </Grid>
        <Grid size={5}>
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
                {labelledHistoryList.map((history, index) => {
                  return (
                    <TableRow key={index}>
                      <TableCell sx={history.style}>{t_i18n(history.label)}</TableCell>
                      <TableCell sx={history.style}>{history.score}</TableCell>
                      <TableCell sx={history.style}>{history.updated_at}</TableCell>
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
