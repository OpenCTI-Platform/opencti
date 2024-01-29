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

  const decayCurveColor = theme.palette.primary.main;
  const reactionPointColor = theme.palette.text.primary;
  const scoreColor = theme.palette.success.main;
  const revokeColor = theme.palette.secondary.main;

  const chartLabelBackgroundColor = theme.palette.background.paper;
  const chartInfoTextColor = theme.palette.text.primary;
  const chartBackgroundColor = theme.palette.background.default;
  const graphLineThickness = 4;

  // Time in millisecond cannot be set as number in GraphQL because it's too long
  // So the time in data is stored as Date and must be converted to time in ms to be drawn on the chart.
  const convertTimeForChart = (time: Date) => {
    return moment(time).valueOf();
  };

  // This is the chart serie data, aka the curve.
  const decayCurveDataPoints: { x: number; y: number }[] = [];
  if (indicator.decayChartData && indicator.decayChartData.live_score_serie) {
    indicator.decayChartData.live_score_serie.forEach((dataPoint) => {
      decayCurveDataPoints.push({
        x: convertTimeForChart(dataPoint.time),
        y: dataPoint.score,
      });
    });
  }

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
            color: reactionPoint === indicator.x_opencti_score ? scoreColor : chartInfoTextColor,
            background: chartLabelBackgroundColor,
          },
          text: `${reactionPoint}`,
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
        text: `Revoke score: ${indicator.decay_applied_rule.decay_revoke_score}`,
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
  if (indicator.decayChartData?.live_score_serie && indicator.decayChartData?.live_score_serie.length > 0) {
    // circle on the curve that show the live score
    pointAnnotations.push({
      x: new Date().getTime(),
      y: indicator.decayLiveDetails?.live_score,
      marker: {
        fillColor: decayCurveColor,
        strokeColor: chartInfoTextColor,
        strokeWidth: 1,
        size: graphLineThickness,
        fillOpacity: 0.2,
      },
    });

    // circle on the curve that show the current stable score
    const currentScore = indicator.decayChartData?.live_score_serie.find((point) => point.score === indicator.x_opencti_score);
    if (currentScore !== undefined) {
      pointAnnotations.push({
        x: convertTimeForChart(currentScore.time),
        y: currentScore.score,
        marker: {
          fillColor: scoreColor,
          strokeColor: chartInfoTextColor,
          size: graphLineThickness + 1,
          strokeWidth: 1,
          fillOpacity: 1,
          radius: graphLineThickness,
        },
        label: {
          text: `Score:${currentScore.score}`,
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
      background: chartBackgroundColor,
      selection: {
        enabled: false,
      },
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
      count: indicator.decayLiveDetails?.live_score,
      fillOpacity: 0.5,
      strokeWidth: graphLineThickness,
      dashArray: 8,
    },
  };

  const series = [
    {
      name: 'Score', // this is the text on the popover
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
