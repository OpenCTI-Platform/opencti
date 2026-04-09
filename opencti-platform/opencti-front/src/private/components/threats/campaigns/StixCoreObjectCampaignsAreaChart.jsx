import React, { useMemo } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import CircularProgress from '@mui/material/CircularProgress';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Chart from '../../common/charts/Chart';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { monthsAgo, now } from '../../../../utils/Time';
import { areaChartOptions } from '../../../../utils/Charts';
import { simpleNumberFormat } from '../../../../utils/Number';
import { NO_DATA_WIDGET_MESSAGE } from '../../../../components/dashboard/WidgetNoData';

const styles = () => ({
  paper: {
    minHeight: 280,
    height: '100%',
    margin: '4px 0 0 0',
    padding: '0 0 10px 0',
    borderRadius: 4,
  },
  chip: {
    fontSize: 10,
    height: 20,
    marginLeft: 10,
  },
});

const stixCoreObjectCampaignsAreaChartTimeSeriesQuery = graphql`
  query StixCoreObjectCampaignsAreaChartTimeSeriesQuery(
    $objectId: String
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: String!
  ) {
    campaignsTimeSeries(
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

const StixCoreObjectCampaignsAreaChart = ({
  t,
  fsd,
  campaignType,
  startDate,
  endDate,
  dateAttribute,
  stixCoreObjectId,
  theme,
  classes,
  title,
  variant,
  height,
}) => {
  const fallbackDates = useMemo(() => ({
    start: monthsAgo(12),
    end: now(),
  }), []);

  const campaignsTimeSeriesVariables = useMemo(() => ({
    authorId: null,
    objectId: stixCoreObjectId,
    campaignType: campaignType || null,
    field: dateAttribute,
    operation: 'count',
    startDate: startDate || fallbackDates.start,
    endDate: endDate || fallbackDates.end,
    interval: 'day',
  }), [startDate, endDate, fallbackDates, stixCoreObjectId, campaignType, dateAttribute]);

  const renderContent = () => {
    return (
      <QueryRenderer
        query={stixCoreObjectCampaignsAreaChartTimeSeriesQuery}
        variables={campaignsTimeSeriesVariables}
        render={({ props }) => {
          if (props && props.campaignsTimeSeries) {
            const chartData = props.campaignsTimeSeries.map((entry) => ({
              x: new Date(entry.date),
              y: entry.value,
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
                    name: t('Number of campigns'),
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
                  {t(NO_DATA_WIDGET_MESSAGE)}
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
        {title || t('Campaigns history')}
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

StixCoreObjectCampaignsAreaChart.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  stixCoreObjectId: PropTypes.string,
  dateAttribute: PropTypes.string,
  t: PropTypes.func,
  md: PropTypes.func,
};

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(StixCoreObjectCampaignsAreaChart);
