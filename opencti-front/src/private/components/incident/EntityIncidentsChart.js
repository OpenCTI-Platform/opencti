import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import AreaChart from 'recharts/lib/chart/AreaChart';
import ResponsiveContainer from 'recharts/lib/component/ResponsiveContainer';
import CartesianGrid from 'recharts/lib/cartesian/CartesianGrid';
import Area from 'recharts/lib/cartesian/Area';
import XAxis from 'recharts/lib/cartesian/XAxis';
import YAxis from 'recharts/lib/cartesian/YAxis';
import Tooltip from 'recharts/lib/component/Tooltip';
import { withStyles } from '@material-ui/core/styles';
import CircularProgress from '@material-ui/core/CircularProgress';
import Chip from '@material-ui/core/Chip';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import { QueryRenderer } from '../../../relay/environment';
import { monthsAgo, now } from '../../../utils/Time';
import Theme from '../../../components/Theme';
import inject18n from '../../../components/i18n';

const styles = () => ({
  paper: {
    minHeight: 300,
    height: '100%',
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
  chip: {
    fontSize: 10,
    height: 20,
    marginLeft: 10,
  },
});

const entityIncidentsChartIncidentsTimeSeriesQuery = graphql`
  query EntityIncidentsChartIncidentsTimeSeriesQuery(
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

class EntityIncidentsChart extends Component {
  constructor(props) {
    super(props);
    this.state = { period: 36, interval: 2 };
  }

  changePeriod(period) {
    let interval = 2;
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
    const {
      t, md, classes, entityId,
    } = this.props;
    const incidentsTimeSeriesVariables = {
      objectId: entityId,
      field: 'first_seen',
      operation: 'count',
      startDate: monthsAgo(this.state.period),
      endDate: now(),
      interval: 'month',
    };
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Incidents')}
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
            query={entityIncidentsChartIncidentsTimeSeriesQuery}
            variables={incidentsTimeSeriesVariables}
            render={({ props }) => {
              if (props && props.incidentsTimeSeries) {
                return (
                  <ResponsiveContainer height={330} width="100%">
                    <AreaChart
                      data={props.incidentsTimeSeries}
                      margin={{
                        top: 20,
                        right: 50,
                        bottom: 20,
                        left: -10,
                      }}
                    >
                      <CartesianGrid strokeDasharray="2 2" stroke="#0f181f" />
                      <XAxis
                        dataKey="date"
                        stroke="#ffffff"
                        interval={this.state.interval}
                        angle={-45}
                        textAnchor="end"
                        tickFormatter={md}
                      />
                      <YAxis stroke="#ffffff" />
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
                      <Area
                        type="monotone"
                        stroke={Theme.palette.primary.main}
                        dataKey="value"
                      />
                    </AreaChart>
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

EntityIncidentsChart.propTypes = {
  entityId: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  md: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(EntityIncidentsChart);
