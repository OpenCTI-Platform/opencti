import React from 'react';
import { graphql } from 'react-relay';
import CircularProgress from '@mui/material/CircularProgress';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/styles';
import Chart from '../charts/Chart';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { monthsAgo, now } from '../../../../utils/Time';
import { lineChartOptions } from '../../../../utils/Charts';
import { simpleNumberFormat } from '../../../../utils/Number';
import { findFilterFromKey } from "../../../../utils/filters/filtersUtils";

const useStyles = makeStyles(() => ({
  paper: {
    minHeight: 280,
    height: '100%',
    margin: '4px 0 0 0',
    padding: '0 0 10px 0',
    borderRadius: 6,
  },
}));

const stixCoreObjectsMultiLineChartTimeSeriesQuery = graphql`
  query StixCoreObjectsMultiLineChartTimeSeriesQuery(
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: String!
    $timeSeriesParameters: [StixCoreObjectsTimeSeriesParameters]
  ) {
    stixCoreObjectsMultiTimeSeries(
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

const StixCoreObjectsMultiLineChart = ({
  variant,
  height,
  startDate,
  endDate,
  dataSelection,
  parameters = {},
  withExportPopover = false,
  isReadOnly = false,
}) => {
  const theme = useTheme();
  const classes = useStyles();
  const { t, fsd, mtdy, yd } = useFormatter();
  const renderContent = () => {
    const timeSeriesParameters = dataSelection.map((selection) => {
      const filtersContent = selection.filters?.filters ?? [];
      const dataSelectionTypes = findFilterFromKey(filtersContent, 'entity_type', 'eq')?.values ?? ['Stix-Core-Object'];
      const dataSelectionObjectId = findFilterFromKey(filtersContent, 'elementId', 'eq')?.values ?? null;
      const dataSelectionRelationshipType = findFilterFromKey(filtersContent, 'relationship_type', 'eq')?.values ?? null;
      const finalFilters = selection.filters ? {
        ...selection.filters,
        filters: filtersContent.filter(
          (n) => ![
            'entity_type',
            'elementId',
            'relationship_type',
            'toTypes',
          ].includes(n.key),
        ),
      } : undefined;
      return {
        field:
          selection.date_attribute && selection.date_attribute.length > 0
            ? selection.date_attribute
            : 'created_at',
        types: dataSelectionTypes,
        filters: finalFilters,
        relationship_type: dataSelectionRelationshipType,
        elementId: dataSelectionObjectId,
      };
    });
    let formatter = fsd;
    if (parameters.interval === 'month' || parameters.interval === 'quarter') {
      formatter = mtdy;
    }
    if (parameters.interval === 'year') {
      formatter = yd;
    }
    return (
      <QueryRenderer
        query={stixCoreObjectsMultiLineChartTimeSeriesQuery}
        variables={{
          operation: 'count',
          startDate: startDate ?? monthsAgo(12),
          endDate: endDate ?? now(),
          interval: parameters.interval ?? 'day',
          timeSeriesParameters,
        }}
        render={({ props }) => {
          if (props && props.stixCoreObjectsMultiTimeSeries) {
            return (
              <Chart
                options={lineChartOptions(
                  theme,
                  !parameters.interval
                    || ['day', 'week'].includes(parameters.interval),
                  formatter,
                  simpleNumberFormat,
                  parameters.interval
                    && !['day', 'week'].includes(parameters.interval)
                    ? 'dataPoints'
                    : undefined,
                  false,
                  parameters.legend,
                )}
                series={dataSelection.map((selection, i) => ({
                  name: selection.label ?? t('Number of entities'),
                  data: props.stixCoreObjectsMultiTimeSeries[i].data.map(
                    (entry) => ({
                      x: new Date(entry.date),
                      y: entry.value,
                    }),
                  ),
                }))}
                type="line"
                width="100%"
                height="100%"
                withExportPopover={withExportPopover}
                isReadOnly={isReadOnly}
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
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
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

export default StixCoreObjectsMultiLineChart;
