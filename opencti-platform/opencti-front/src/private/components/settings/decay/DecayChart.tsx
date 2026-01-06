import React, { FunctionComponent } from 'react';
import Chart from '@components/common/charts/Chart';
import { ApexOptions } from 'apexcharts';
import moment from 'moment';
import { useTheme } from '@mui/styles';
import { Theme } from '@mui/material/styles/createTheme';
import { useFormatter } from '../../../../components/i18n';

export interface DecayHistory {
  score: number;
  updated_at: Date;
}

interface DecayChartProps {
  currentScore?: number;
  decayCurvePoint?: DecayHistory[];
  decayLiveScore?: number;
  revokeScore: number;
  reactionPoints?: number[];
}

const DecayChart: FunctionComponent<DecayChartProps> = ({ currentScore, decayCurvePoint, decayLiveScore, revokeScore, reactionPoints }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();

  const decayCurveColor = theme.palette.primary.main;
  const reactionPointColor = theme.palette.text.primary;
  const scoreColor = theme.palette.success.main;
  const revokeColor = theme.palette.secondary.main;

  const chartLabelBackgroundColor = theme.palette.background.paper;
  const chartInfoTextColor = theme.palette.text.primary;
  const graphLineThickness = 3;

  // Time in millisecond cannot be set as number in GraphQL because it's too long
  // So the time in data is stored as Date and must be converted to time in ms to be drawn on the chart.
  const convertTimeForChart = (time: Date) => {
    return moment(time).valueOf();
  };

  // This is the chart serie data, aka the curve.
  const decayCurveDataPoints: { x: number; y: number }[] = [];
  if (decayCurvePoint) {
    decayCurvePoint.forEach((dataPoint) => {
      decayCurveDataPoints.push({
        x: convertTimeForChart(dataPoint.updated_at),
        y: dataPoint.score,
      });
    });
  }

  const graphLinesAnnotations = [];
  // Horizontal lines that shows reaction points
  if (reactionPoints) {
    const currentScoreIndex = reactionPoints.findLastIndex((reactionPoint) => reactionPoint === currentScore);
    reactionPoints.forEach((reactionPoint, index) => {
      const lineReactionValue = {
        y: reactionPoint,
        borderColor: index === currentScoreIndex ? scoreColor : reactionPointColor,
        label: {
          borderColor: index === currentScoreIndex ? scoreColor : reactionPointColor,
          offsetY: 0,
          style: {
            color: index === currentScoreIndex ? scoreColor : chartInfoTextColor,
            background: chartLabelBackgroundColor,
          },
          text: `${reactionPoint}`,
        },
      };
      graphLinesAnnotations.push(lineReactionValue);
    });

    // Horizontal "red" area that show the revoke zone
    const revokeScoreArea = {
      y: revokeScore + 1, // trick to have a red line even if revoke score is 0
      y2: 0,
      borderColor: revokeColor,
      fillColor: revokeColor,
      label: {
        text: `${t_i18n('Revoke score:')} ${revokeScore}`,
        borderColor: revokeColor,
        style: {
          color: revokeColor,
          background: chartLabelBackgroundColor,
        },
      },
    };
    graphLinesAnnotations.push(revokeScoreArea);
  }

  const pointAnnotations = [];
  if (decayCurvePoint && decayCurvePoint.length > 0) {
    // circle on the curve that show the live score
    pointAnnotations.push({
      x: new Date().getTime(),
      y: decayLiveScore,
      marker: {
        fillColor: decayCurveColor,
        strokeColor: chartInfoTextColor,
        strokeWidth: 1,
        size: graphLineThickness,
        fillOpacity: 0.2,
      },
    });

    // circle on the curve that show the current stable score
    const currentScoreData = decayCurvePoint.findLast((point) => point.score === currentScore);
    if (currentScoreData !== undefined) {
      pointAnnotations.push({
        x: convertTimeForChart(currentScoreData.updated_at),
        y: currentScoreData.score,
        marker: {
          fillColor: scoreColor,
          strokeColor: chartInfoTextColor,
          size: graphLineThickness + 1,
          strokeWidth: 1,
          fillOpacity: 1,
          radius: graphLineThickness,
        },
        label: {
          text: `${t_i18n('Score:')} ${currentScoreData.score}`,
          position: 'right',
          borderColor: scoreColor,
          borderWidth: 2,
          style: {
            color: scoreColor,
            background: chartLabelBackgroundColor,
          },
        },
      });
    }
  }

  const chartOptions: ApexOptions = {
    chart: {
      id: 'Decay graph',
      toolbar: { show: false },
      type: 'line',
      selection: { enabled: false },
      zoom: { enabled: false },
    },
    xaxis: {
      type: 'datetime',
      title: {
        text: t_i18n('Days'),
        style: {
          color: chartInfoTextColor,
        },
      },
      labels: {
        style: {
          colors: chartInfoTextColor,
        },
        datetimeFormatter: {
          year: 'yyyy',
          month: 'MMM yyyy',
          day: 'dd MMM yyyy',
        },
      },
    },
    yaxis: {
      min: 0,
      max: 100,
      title: {
        text: t_i18n('Score'),
        style: {
          color: chartInfoTextColor,
        },
      },
      labels: {
        style: {
          colors: chartInfoTextColor,
        },
      },
    },
    annotations: {
      yaxis: graphLinesAnnotations,
      points: pointAnnotations,
    },
    grid: { show: false },
    colors: [
      decayCurveColor,
    ],
    tooltip: {
      theme: theme.palette.mode, // ApexChart uses 'dark'/'light', exactly the same values as we use in OpenCTI.
      x: {
        show: true,
        format: 'dd MMM yyyy',
      },
    },
    forecastDataPoints: {
      // this draw the dash line after live score point
      count: decayLiveScore && decayLiveScore > 1 ? decayLiveScore - 2 : 0,
      fillOpacity: 0.5,
      strokeWidth: graphLineThickness,
      dashArray: 8,
    },
  };

  const series = [
    {
      name: t_i18n('Score'), // this is the text on the popover
      data: decayCurveDataPoints,
    },
  ];

  return (
    <Chart
      series={series}
      options={chartOptions}
    />
  );
};

export default DecayChart;
