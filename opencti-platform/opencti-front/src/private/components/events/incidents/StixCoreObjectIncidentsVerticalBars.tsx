// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck : TODO: need to migrate Charts.js file to .ts
import React, {FunctionComponent} from 'react';
import {graphql} from 'react-relay';
import CircularProgress from '@mui/material/CircularProgress';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Chart from 'react-apexcharts';
import makeStyles from '@mui/styles/makeStyles';
import {useTheme} from '@mui/styles';
import {QueryRenderer} from '../../../../relay/environment';
import {monthsAgo, now} from '../../../../utils/Time';
import {verticalBarsChartOptions} from '../../../../utils/Charts';
import {simpleNumberFormat} from '../../../../utils/Number';
import {useFormatter} from '../../../../components/i18n';
import {Theme} from '../../../../components/Theme';
import {StatsOperation,} from './__generated__/StixCoreObjectIncidentsAreaChartTimeSeriesQuery.graphql';
import {
  StixCoreObjectIncidentsVerticalBarsTimeSeriesQuery$data,
} from './__generated__/StixCoreObjectIncidentsVerticalBarsTimeSeriesQuery.graphql';

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

const StixCoreObjectIncidentsVerticalBarsTimeSeriesQuery = graphql`
    query StixCoreObjectIncidentsVerticalBarsTimeSeriesQuery(
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
interface IncidentsVerticalBarsProps {
  stixCoreObjectId: string,
  dateAttribute: string,
  variant?: string,
  height: string,
  title: string,
  incidentType: string,
  startDate: string,
  endDate: string,

}

const IncidentsVerticalBars: FunctionComponent<IncidentsVerticalBarsProps> = ({ stixCoreObjectId, variant, height,
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
    const incidentsTimeSeriesVariables = {
      authorId: null,
      objectId: stixCoreObjectId,
      incidentType: incidentType || null,
      field: 'created_at',
      operation: 'count' as StatsOperation,
      startDate: finalStartDate,
      endDate: finalEndDate,
      interval,
    };
    return (
      <QueryRenderer
        query={StixCoreObjectIncidentsVerticalBarsTimeSeriesQuery}
        variables={incidentsTimeSeriesVariables}
        render={({ props }: { props: StixCoreObjectIncidentsVerticalBarsTimeSeriesQuery$data }) => {
          if (props && props.incidentsTimeSeries) {
            const chartData = props.incidentsTimeSeries.map((entry) => ({
              x: new Date(entry?.date),
              y: entry?.value,
            }));
            return (
              <Chart
                options={verticalBarsChartOptions(
                  theme,
                  fsd,
                  simpleNumberFormat,
                  false,
                  true,
                )}
                series={[
                  {
                    name: t('Number of incidents'),
                    data: chartData,
                  },
                ]}
                type="bar"
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

export default IncidentsVerticalBars;
