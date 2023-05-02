import React from 'react';
import { graphql } from 'react-relay';
import CircularProgress from '@mui/material/CircularProgress';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/styles';
import * as R from 'ramda';
import Chart from '../charts/Chart';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { monthsAgo, now } from '../../../../utils/Time';
import { heatMapOptions } from '../../../../utils/Charts';
import { convertFilters } from '../../../../utils/ListParameters';

const useStyles = makeStyles(() => ({
  paper: {
    minHeight: 280,
    height: '100%',
    margin: '4px 0 0 0',
    padding: '0 0 10px 0',
    borderRadius: 6,
  },
  chip: {
    fontSize: 10,
    height: 20,
    marginLeft: 10,
  },
}));

const stixCoreRelationshipsMultiHeatMapTimeSeriesQuery = graphql`
  query StixCoreRelationshipsMultiHeatMapTimeSeriesQuery(
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: String!
    $timeSeriesParameters: [StixCoreRelationshipsTimeSeriesParameters]
  ) {
    stixCoreRelationshipsMultiTimeSeries(
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      interval: $interval
      timeSeriesParameters: $timeSeriesParameters
    ) {
      data {
        date
        value
      }
    }
  }
`;

const darkColors = [
  '#001e3c',
  '#023362',
  '#02407a',
  '#045198',
  '#0561b4',
  '#0b75d9',
  '#2986e7',
  '#3a95f3',
  '#4da3ff',
  '#76bbff',
  '#9eccff',
];

const lightColors = [
  '#f3f6f9',
  '#76bbff',
  '#4da3ff',
  '#3a95f3',
  '#2986e7',
  '#0b75d9',
  '#0561b4',
  '#02407a',
  '#023362',
  '#001e3c',
  '#021428',
];

const StixCoreRelationshipsMultiHeatMap = ({
  variant,
  height,
  startDate,
  endDate,
  dataSelection,
  parameters = {},
}) => {
  const theme = useTheme();
  const classes = useStyles();
  const { t, fsd } = useFormatter();
  const renderContent = () => {
    const timeSeriesParameters = dataSelection.map((selection) => {
      const filters = convertFilters(selection.filters);
      const dataSelectionDateAttribute = selection.date_attribute && selection.date_attribute.length > 0
        ? selection.date_attribute
        : 'created_at';
      const dataSelectionRelationshipType = R.head(filters.filter((n) => n.key === 'relationship_type'))?.values
        || null;
      const dataSelectionFromId = R.head(filters.filter((n) => n.key === 'fromId'))?.values || null;
      const dataSelectionToId = R.head(filters.filter((n) => n.key === 'toId'))?.values || null;
      const dataSelectionFromTypes = R.head(filters.filter((n) => n.key === 'fromTypes'))?.values || null;
      const dataSelectionToTypes = R.head(filters.filter((n) => n.key === 'toTypes'))?.values || null;
      const finalFilters = filters.filter(
        (n) => ![
          'relationship_type',
          'fromId',
          'toId',
          'fromTypes',
          'toTypes',
        ].includes(n.key),
      );
      return {
        fromId: dataSelectionFromId,
        toId: dataSelectionToId,
        relationship_type: dataSelectionRelationshipType,
        fromTypes: dataSelectionFromTypes,
        toTypes: dataSelectionToTypes,
        field: dataSelectionDateAttribute,
        filters: finalFilters,
      };
    });
    return (
      <QueryRenderer
        query={stixCoreRelationshipsMultiHeatMapTimeSeriesQuery}
        variables={{
          operation: 'count',
          startDate: startDate ?? monthsAgo(12),
          endDate: endDate ?? now(),
          interval: parameters.interval ?? 'day',
          timeSeriesParameters,
        }}
        render={({ props }) => {
          if (props && props.stixCoreRelationshipsMultiTimeSeries) {
            const chartdata = dataSelection.map((selection, i) => ({
              name: selection.label ?? t('Number of relationships'),
              data: props.stixCoreRelationshipsMultiTimeSeries[i].data.map(
                (entry) => ({
                  x: new Date(entry.date),
                  y: entry.value,
                }),
              ),
            }));
            const allValues = props.stixCoreRelationshipsMultiTimeSeries
              .map((n) => n.data.map((o) => o.value))
              .flat();
            const maxValue = Math.max(...allValues);
            const minValue = Math.min(...allValues);
            const interval = Math.trunc((maxValue - minValue) / 9);
            const colorRanges = Array(10)
              .fill(0)
              .map((_, i) => ({
                from:
                  minValue + (i + 1) * interval - interval === 0
                    ? 1
                    : minValue + (i + 1) * interval - interval,
                to: minValue + (i + 1) * interval,
                color:
                  theme.palette.mode === 'dark'
                    ? darkColors[i + 1]
                    : lightColors[i + 1],
              }));
            colorRanges.push({
              from: 0,
              to: 0,
              color:
                theme.palette.mode === 'dark' ? darkColors[0] : lightColors[0],
            });
            return (
              <Chart
                options={heatMapOptions(
                  theme,
                  true,
                  fsd,
                  undefined,
                  undefined,
                  parameters.stacked,
                  colorRanges,
                )}
                series={chartdata}
                type="heatmap"
                width="100%"
                height="100%"
                withExportPopover={true}
              />
            );
          }
          if (props) {
            return (
              <div style={{ display: 'table', height: '100%', width: '100%' }}>
                <span
                  style={{
                    display: 'table-cell',
                    verticalAlign: 'middle',
                    textAlign: 'center',
                  }}
                >
                  {t('No entities of this type has been found.')}
                </span>
              </div>
            );
          }
          return (
            <div style={{ display: 'table', height: '100%', width: '100%' }}>
              <span
                style={{
                  display: 'table-cell',
                  verticalAlign: 'middle',
                  textAlign: 'center',
                }}
              >
                <CircularProgress size={40} thickness={2} />
              </span>
            </div>
          );
        }}
      />
    );
  };
  return (
    <div style={{ height: height || '100%' }}>
      <Typography
        variant="h4"
        gutterBottom={true}
        style={{
          margin: variant !== 'inLine' ? '0 0 10px 0' : '-10px 0 10px -7px',
        }}
      >
        {parameters.title ?? t('Entities history')}
      </Typography>
      {variant !== 'inLine' ? (
        <Paper classes={{ root: classes.paper }} variant="outlined">
          {renderContent()}
        </Paper>
      ) : (
        renderContent()
      )}
    </div>
  );
};

export default StixCoreRelationshipsMultiHeatMap;
