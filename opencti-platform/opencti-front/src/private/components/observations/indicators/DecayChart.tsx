import React, { FunctionComponent } from 'react';
import { IndicatorDetails_indicator$data } from '@components/observations/indicators/__generated__/IndicatorDetails_indicator.graphql';
import Chart from '@components/common/charts/Chart';
import { ApexOptions } from 'apexcharts';
import moment from 'moment';
import { useTheme } from '@mui/styles';
import { Theme } from '@mui/material/styles/createTheme';

interface DecayChartProps {
  indicator: IndicatorDetails_indicator$data,
}

const DecayChart : FunctionComponent<DecayChartProps> = ({ indicator }) => {
  const theme = useTheme<Theme>();

  const liveScoreColor = theme.palette.success.main;
  const reactionPointColor = theme.palette.text.primary;
  const scoreColor = theme.palette.info.main;
  const revokeColor = theme.palette.secondary.main;

  const chartLabelsTextColor = theme.palette.info.contrastText;
  const chartInfoTextColor = theme.palette.text.primary;
  const chartBackgroundColor = theme.palette.background.default;

  const graphLinesAnnotations = [];

  // Horizontal lines that shows reaction points
  if (indicator.decay_applied_rule?.decay_points) {
    indicator.decay_applied_rule.decay_points.forEach((reactionPoint) => {
      const lineReactionValue = {
        y: reactionPoint,
        borderColor: reactionPoint === indicator.x_opencti_score ? scoreColor : reactionPointColor,
        label: {
          borderColor: reactionPoint === indicator.x_opencti_score ? scoreColor : reactionPointColor,
          offsetY: 0,
          style: {
            color: chartLabelsTextColor,
            background: reactionPoint === indicator.x_opencti_score ? scoreColor : reactionPointColor,
          },
          text: reactionPoint === indicator.x_opencti_score ? `Score: ${reactionPoint}` : `${reactionPoint}`,
        },
      };
      graphLinesAnnotations.push(lineReactionValue);
    });

    // Horizontal "red" area that show the revoke zone
    const revokeScoreArea = {
      y: indicator.decay_applied_rule.decay_revoke_score + 1, // trick to have a red line even if revoke score is 0
      y2: 0,
      borderColor: revokeColor,
      fillColor: revokeColor,
      label: {
        text: `Revoke zone: ${indicator.decay_applied_rule.decay_revoke_score}`,
        borderColor: revokeColor,
        style: {
          color: chartLabelsTextColor,
          background: revokeColor,
        },
      },
    };
    graphLinesAnnotations.push(revokeScoreArea);
  }

  // Horizontal line that the current / live score
  const liveScoreLine = {
    y: indicator.decayLiveDetails?.live_score,
    borderColor: liveScoreColor,
    label: {
      borderColor: liveScoreColor,
      style: {
        color: chartLabelsTextColor,
        background: liveScoreColor,
      },
      text: `Live score:${indicator.decayLiveDetails?.live_score}`,
    },
  };
  graphLinesAnnotations.push(liveScoreLine);

  // Time in millisecond cannot be set as number in GraphQL because it's too long
  // So the time in data is stored as Date and must be converted to time in ms to be drawn on the chart.
  const liveScoreApexFormat: { x: number; y: number }[] = [];
  if (indicator.decayChartData && indicator.decayChartData.live_score_serie) {
    indicator.decayChartData.live_score_serie.forEach((dataPoint) => {
      liveScoreApexFormat.push({
        x: moment(dataPoint.time).valueOf(),
        y: dataPoint.score,
      });
    });
  }

  const pointAnnotations = [];
  // circle on the curve that show the live score
  pointAnnotations.push({
    x: new Date().getTime(),
    y: indicator.decayLiveDetails?.live_score,
    marker: {
      fillColor: liveScoreColor,
    },
  });

  // circle on the curve that show first and last point
  if (indicator.decayChartData?.live_score_serie) {
    const serie = indicator.decayChartData?.live_score_serie;
    pointAnnotations.push({
      x: moment(serie[0].time).valueOf(),
      y: serie[0].score,
      marker: {
        fillColor: chartInfoTextColor,
      },
    });

    pointAnnotations.push({
      x: moment(serie[serie.length - 1].time).valueOf(),
      y: serie[serie.length - 1].score,
      marker: {
        fillColor: chartInfoTextColor,
      },
    });
  }

  console.log('pointAnnotations', pointAnnotations);

  const chartOptions: ApexOptions = {
    chart: {
      id: 'Decay graph',
      toolbar: { show: false },
      type: 'line',
      background: chartBackgroundColor,
    },
    xaxis: {
      type: 'datetime',
      title: {
        text: 'Days',
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
        text: 'Score',
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
      theme.palette.primary.main,
    ],
    stroke: {
      curve: 'smooth',
    },
    tooltip: {
      theme: theme.palette.mode, // ApexChart uses 'dark'/'light', exactly the same values as we use in OpenCTI.
      x: {
        show: true,
        format: 'dd MMM yyyy',
      },
    },
  };

  const series = [
    {
      name: 'Score with decay', // this is the text on the popover
      data: liveScoreApexFormat,
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
