import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import {
  ResponsiveContainer,
  CartesianGrid,
  AreaChart,
  XAxis,
  YAxis,
  Area,
  Tooltip,
} from 'recharts';
import { withStyles, withTheme } from '@material-ui/core/styles';
import CircularProgress from '@material-ui/core/CircularProgress';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { monthsAgo, now, numberOfDays } from '../../../../utils/Time';

const styles = () => ({
  paper: {
    minHeight: 280,
    height: '100%',
    margin: '4px 0 0 0',
    padding: '1rem',
    borderRadius: 6,
  },
  chip: {
    fontSize: 10,
    height: 20,
    marginLeft: 10,
  },
});

const cyioCoreObjectTotalComponentsLineChartQuery = graphql`
  query CyioCoreObjectTotalComponentsLineChartQuery(
    $type: String
    $field: String!
    $match: [String]
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: Interval!
  ) {
    assetsTimeSeries(
      type: $type
      match: $match
      field: $field
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      interval: $interval
    ) {
      date
      label
      value
    }
  }
`;

class CyioCoreObjectTotalComponentsLineChart extends Component {
  renderContent() {
    const {
      t,
      md,
      nsd,
      startDate,
      endDate,
      theme,
    } = this.props;
    const interval = 'month';
    const finalStartDate = startDate || monthsAgo(12);
    const finalEndDate = endDate || now();
    const days = numberOfDays(finalStartDate, finalEndDate);
    let tickFormatter = md;
    if (days <= 30) {
      tickFormatter = nsd;
    }
    const assetsTimeSeriesVariables = {
      type: 'Component',
      field: 'component_type',
      match: ['software', 'network'],
      operation: 'count',
      startDate: finalStartDate,
      endDate: finalEndDate,
      interval,
    };
    return (
      <QueryRenderer
        query={cyioCoreObjectTotalComponentsLineChartQuery}
        variables={assetsTimeSeriesVariables}
        render={({ props }) => {
          if (props && props.assetsTimeSeries) {
            return (
              <ResponsiveContainer height="100%" width="100%">
                <AreaChart
                  data={props.assetsTimeSeries}
                  margin={{
                    top: 20,
                    right: 0,
                    bottom: 20,
                    left: -10,
                  }}
                >
                  <CartesianGrid
                    strokeDasharray="2 2"
                    // stroke={theme.palette.primary.main}
                    stroke="rgba(241, 241, 242, 0.35)"
                    vertical={false}
                  />
                  <XAxis
                    dataKey='label'
                    stroke={theme.palette.text.primary}
                    interval={interval}
                    textAnchor="end"
                  // angle={-30}
                  // tickFormatter={tickFormatter}
                  />
                  <YAxis dataKey='value' stroke={theme.palette.text.primary} />
                  <Tooltip
                    cursor={{
                      fill: 'rgba(0, 0, 0, 0.2)',
                      stroke: 'rgba(0, 0, 0, 0.2)',
                      strokeWidth: 2,
                    }}
                    contentStyle={{
                      backgroundColor: '#1F2842',
                      fontSize: 12,
                      border: '1px solid #06102D',
                      borderRadius: 10,
                    }}
                  // labelFormatter={tickFormatter}
                  />
                  <Area
                    dataKey="value"
                    stroke={theme.palette.primary.main}
                    strokeWidth={2}
                  // fill={theme.palette.primary.main}
                  />
                </AreaChart>
              </ResponsiveContainer>
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
  }

  render() {
    const {
      t, classes, title, variant, height,
    } = this.props;
    return (
      <div style={{ height: height || '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {title || t('Total Components')}
        </Typography>
        {variant !== 'inLine' ? (
          <Paper classes={{ root: classes.paper }} elevation={2}>
            {this.renderContent()}
          </Paper>
        ) : (
          this.renderContent()
        )}
      </div>
    );
  }
}

CyioCoreObjectTotalComponentsLineChart.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  md: PropTypes.func,
  nsd: PropTypes.func,
};

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(CyioCoreObjectTotalComponentsLineChart);
