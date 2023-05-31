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
import { lineChartOptions } from '../../../../utils/Charts';
import { simpleNumberFormat } from '../../../../utils/Number';
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

const stixCoreRelationshipsMultiLineChartTimeSeriesQuery = graphql`
  query StixCoreRelationshipsMultiLineChartTimeSeriesQuery(
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

const StixCoreRelationshipsMultiLineChart = ({
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
        query={stixCoreRelationshipsMultiLineChartTimeSeriesQuery}
        variables={{
          operation: 'count',
          startDate: startDate ?? monthsAgo(12),
          endDate: endDate ?? now(),
          interval: parameters.interval ?? 'day',
          timeSeriesParameters,
        }}
        render={({ props }) => {
          if (props && props.stixCoreRelationshipsMultiTimeSeries) {
            return (
              <Chart
                options={lineChartOptions(
                  theme,
                  true,
                  fsd,
                  simpleNumberFormat,
                  undefined,
                  false,
                  parameters.legend,
                )}
                series={dataSelection.map((selection, i) => ({
                  name: selection.label ?? t('Number of entities'),
                  data: props.stixCoreRelationshipsMultiTimeSeries[i].data.map(
                    (entry) => ({
                      x: new Date(entry.date),
                      y: entry.value,
                    }),
                  ),
                }))}
                type="line"
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

export default StixCoreRelationshipsMultiLineChart;
