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
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import { QueryRenderer } from '../../../relay/environment';
import { now, yearsAgo } from '../../../utils/Time';
import Theme from '../../../components/Theme';
import inject18n from '../../../components/i18n';

const styles = theme => ({
  paper: {
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: 0,
    backgroundColor: theme.palette.paper.background,
    color: theme.palette.text.main,
    borderRadius: 6,
  },
});

const entityIncidentsChartIncidentsTimeSeriesQuery = graphql`
    query EntityIncidentsChartIncidentsTimeSeriesQuery($objectId: String, $field: String!, $operation: StatsOperation!, $startDate: DateTime!, $endDate: DateTime!, $interval: String!) {
        incidentsTimeSeries(objectId: $objectId, field: $field, operation: $operation, startDate: $startDate, endDate: $endDate, interval: $interval) {
            date,
            value
        }
    }
`;

class EntityIncidentsChart extends Component {
  render() {
    const {
      t, md, classes, entityId,
    } = this.props;
    const incidentsTimeSeriesVariables = {
      objectId: entityId,
      field: 'first_seen',
      operation: 'count',
      startDate: yearsAgo(3),
      endDate: now(),
      interval: 'month',
    };
    return (
      <div style={{ height: '100%' }}>
        <Typography variant='h4' gutterBottom={true}>
          {t('Incidents')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <QueryRenderer
            query={entityIncidentsChartIncidentsTimeSeriesQuery}
            variables={incidentsTimeSeriesVariables}
            render={({ props }) => {
              if (props && props.incidentsTimeSeries) {
                return (
                  <ResponsiveContainer height={330} width='100%'>
                    <AreaChart data={props.incidentsTimeSeries} margin={{
                      top: 20, right: 50, bottom: 20, left: -10,
                    }}>
                      <CartesianGrid strokeDasharray='3 3'/>
                      <XAxis dataKey='date' stroke='#ffffff' interval={2} angle={-45} textAnchor='end' tickFormatter={md}/>
                      <YAxis stroke='#ffffff'/>
                      <Tooltip
                        cursor={{ fill: 'rgba(0, 0, 0, 0.2)', stroke: 'rgba(0, 0, 0, 0.2)', strokeWidth: 2 }}
                        contentStyle={{ backgroundColor: 'rgba(255, 255, 255, 0.1)', fontSize: 12, borderRadius: 10 }}
                        labelFormatter={md}
                      />
                      <Area type='monotone' stroke={Theme.palette.primary.main} dataKey='value'/>
                    </AreaChart>
                  </ResponsiveContainer>
                );
              }
              return (
                <div> &nbsp; </div>
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
