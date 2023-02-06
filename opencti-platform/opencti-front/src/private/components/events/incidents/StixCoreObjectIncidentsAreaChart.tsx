import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import CircularProgress from '@mui/material/CircularProgress';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Chart from 'react-apexcharts';
import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/styles';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { monthsAgo, now } from '../../../../utils/Time';
import { areaChartOptions } from '../../../../utils/Charts';
import { simpleNumberFormat } from '../../../../utils/Number';
import { Theme } from '../../../../components/Theme';
import {
  StatsOperation, StixCoreObjectIncidentsAreaChartTimeSeriesQuery$data,
} from './__generated__/StixCoreObjectIncidentsAreaChartTimeSeriesQuery.graphql';


const useStyles = makeStyles<Theme>(() => ({
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

const stixCoreObjectIncidentsAreaChartTimeSeriesQuery = graphql`
    query StixCoreObjectIncidentsAreaChartTimeSeriesQuery(
        $objectId: String
        $field: String!
        $operation: StatsOperation!
        $startDate: DateTime!
        $endDate: DateTime!
        $interval: String!
    ) {
        incidentsTimeSeries(
            objectId: $objectId
            field: $field
            operation: $operation
            startDate: $startDate
            endDate: $endDate
            interval: $interval
        ) {
            date
            value
        }
    }
`;
interface StixCoreObjectIncidentsAreaChartProps {
  stixCoreObjectId: string,
  dateAttribute: string,
  variant?: string,
  height: string,
  title: string,
  incidentType: string,
  startDate: string,
  endDate: string,

}

const StixCoreObjectIncidentsAreaChart: FunctionComponent<StixCoreObjectIncidentsAreaChartProps> = ({ stixCoreObjectId, dateAttribute, variant, height,
  title,
  startDate,
  endDate,
  incidentType }) => {
  const classes = useStyles();
  const theme = useTheme();
  const { t, fsd } = useFormatter();

  const renderContent = () => {
    const interval = 'day';
    const finalStartDate = startDate || monthsAgo(12);
    const finalEndDate = endDate || now();
    const statsOperation: StatsOperation = 'count';
    const incidentsTimeSeriesVariables = {
      authorId: null,
      objectId: stixCoreObjectId,
      incidentType: incidentType || null,
      field: dateAttribute,
      operation: statsOperation,
      startDate: finalStartDate,
      endDate: finalEndDate,
      interval,
    };
    return (
      <QueryRenderer
        query={stixCoreObjectIncidentsAreaChartTimeSeriesQuery}
        variables={incidentsTimeSeriesVariables}
        render={({ props }: { props: StixCoreObjectIncidentsAreaChartTimeSeriesQuery$data }) => {
          if (props && props.incidentsTimeSeries) {
            const chartData = props.incidentsTimeSeries.map((entry) => ({
              x: new Date(entry?.date),
              y: entry?.value,
            }));
            return (
              <Chart
                options={areaChartOptions(
                  theme,
                  true,
                  fsd,
                  simpleNumberFormat,
                  undefined,
                )}
                series={[
                  {
                    name: t('Number of incidents'),
                    data: chartData,
                  },
                ]}
                type="area"
                width="100%"
                height="100%"
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
        {title || t('Incidents history')}
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

export default StixCoreObjectIncidentsAreaChart;
