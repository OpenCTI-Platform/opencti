import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import {
  BarChart,
  ResponsiveContainer,
  CartesianGrid,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
} from 'recharts';
import withStyles from '@mui/styles/withStyles';
import withTheme from '@mui/styles/withTheme';
import CircularProgress from '@mui/material/CircularProgress';
import Chip from '@mui/material/Chip';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import { QueryRenderer } from '../../../../relay/environment';
import { now, monthsAgo } from '../../../../utils/Time';
import inject18n from '../../../../components/i18n';

const styles = () => ({
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
});

const stixCoreObjectIndicatorsChartIndicatorsTimeSeriesQuery = graphql`
  query StixCoreObjectIndicatorsChartIndicatorsTimeSeriesQuery(
    $objectId: String
    $pattern_type: String
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: String!
  ) {
    indicatorsTimeSeries(
      objectId: $objectId
      pattern_type: $pattern_type
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

class StixCoreObjectIndicatorsChart extends Component {
  constructor(props) {
    super(props);
    this.state = { period: 36, interval: 2 };
  }

  changePeriod(period) {
    let interval;
    switch (period) {
      case 12:
        interval = 0;
        break;
      case 24:
        interval = 1;
        break;
      case 36:
        interval = 2;
        break;
      default:
        interval = 2;
    }
    this.setState({ period, interval });
  }

  render() {
    const { t, md, classes, stixCoreObjectId, indicatorType, theme } = this.props;
    const indicatorsTimeSeriesVariables = {
      authorId: null,
      objectId: stixCoreObjectId,
      indicatorType: indicatorType || null,
      field: 'published',
      operation: 'count',
      startDate: monthsAgo(this.state.period),
      endDate: now(),
      interval: 'month',
    };
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Indicators')}
        </Typography>
        <div style={{ float: 'right', marginTop: -6 }}>
          <Chip
            classes={{ root: classes.chip }}
            style={{
              backgroundColor: this.state.period === 12 ? '#795548' : '#757575',
            }}
            label="12M"
            component="button"
            onClick={this.changePeriod.bind(this, 12)}
          />
          <Chip
            classes={{ root: classes.chip }}
            style={{
              backgroundColor: this.state.period === 24 ? '#795548' : '#757575',
            }}
            label="24M"
            component="button"
            onClick={this.changePeriod.bind(this, 24)}
          />
          <Chip
            classes={{ root: classes.chip }}
            style={{
              backgroundColor: this.state.period === 36 ? '#795548' : '#757575',
            }}
            label="36M"
            component="button"
            onClick={this.changePeriod.bind(this, 36)}
          />
        </div>
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <QueryRenderer
            query={stixCoreObjectIndicatorsChartIndicatorsTimeSeriesQuery}
            variables={indicatorsTimeSeriesVariables}
            render={({ props }) => {
              if (props && props.indicatorsTimeSeries) {
                return (
                  <ResponsiveContainer height="100%" width="100%">
                    <BarChart
                      data={props.indicatorsTimeSeries}
                      margin={{
                        top: 20,
                        right: 50,
                        bottom: 0,
                        left: -10,
                      }}
                    >
                      <CartesianGrid
                        strokeDasharray="2 2"
                        stroke={theme.palette.action.grid}
                      />
                      <XAxis
                        dataKey="date"
                        stroke={theme.palette.text.primary}
                        interval={this.state.interval}
                        angle={-45}
                        textAnchor="end"
                        tickFormatter={md}
                      />
                      <YAxis stroke={theme.palette.text.primary} />
                      <Tooltip
                        cursor={{
                          fill: 'rgba(0, 0, 0, 0.2)',
                          stroke: 'rgba(0, 0, 0, 0.2)',
                          strokeWidth: 2,
                        }}
                        contentStyle={{
                          backgroundColor: 'rgba(255, 255, 255, 0.1)',
                          fontSize: 12,
                          borderRadius: 10,
                        }}
                        labelFormatter={md}
                      />
                      <Bar
                        fill={theme.palette.primary.main}
                        dataKey="value"
                        barSize={5}
                      />
                    </BarChart>
                  </ResponsiveContainer>
                );
              }
              if (props) {
                return (
                  <div
                    style={{ display: 'table', height: '100%', width: '100%' }}
                  >
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
                <div
                  style={{ display: 'table', height: '100%', width: '100%' }}
                >
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
        </Paper>
      </div>
    );
  }
}

StixCoreObjectIndicatorsChart.propTypes = {
  stixCoreObjectId: PropTypes.string,
  classes: PropTypes.object,
  theme: PropTypes.object,
  indicatorType: PropTypes.string,
  t: PropTypes.func,
  md: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(StixCoreObjectIndicatorsChart);
