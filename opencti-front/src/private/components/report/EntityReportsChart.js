import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import BarChart from 'recharts/lib/chart/BarChart';
import ResponsiveContainer from 'recharts/lib/component/ResponsiveContainer';
import CartesianGrid from 'recharts/lib/cartesian/CartesianGrid';
import Bar from 'recharts/lib/cartesian/Bar';
import XAxis from 'recharts/lib/cartesian/XAxis';
import YAxis from 'recharts/lib/cartesian/YAxis';
import Tooltip from 'recharts/lib/component/Tooltip';
import { withStyles } from '@material-ui/core/styles';
import CircularProgress from '@material-ui/core/CircularProgress';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import { QueryRenderer } from '../../../relay/environment';
import { now, yearsAgo } from '../../../utils/Time';
import Theme from '../../../components/Theme';
import inject18n from '../../../components/i18n';

const styles = theme => ({
  paper: {
    minHeight: 300,
    height: '100%',
    margin: '10px 0 0 0',
    padding: '0 0 10px 0',
    backgroundColor: theme.palette.paper.background,
    color: theme.palette.text.main,
    borderRadius: 6,
  },
});

const entityReportsChartReportsTimeSeriesQuery = graphql`
    query EntityReportsChartReportsTimeSeriesQuery($objectId: String, $reportClass: String, $field: String!, $operation: StatsOperation!, $startDate: DateTime!, $endDate: DateTime!, $interval: String!) {
        reportsTimeSeries(objectId: $objectId, reportClass: $reportClass, field: $field, operation: $operation, startDate: $startDate, endDate: $endDate, interval: $interval) {
            date,
            value
        }
    }
`;

class EntityReportsChart extends Component {
  render() {
    const {
      t, md, classes, entityId, reportClass,
    } = this.props;
    const reportsTimeSeriesVariables = {
      objectId: entityId,
      reportClass: reportClass || null,
      field: 'published',
      operation: 'count',
      startDate: yearsAgo(3),
      endDate: now(),
      interval: 'month',
    };
    return (
      <div style={{ height: '100%' }}>
        <Typography variant='h4' gutterBottom={true}>
          {t('Reports')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <QueryRenderer
            query={entityReportsChartReportsTimeSeriesQuery}
            variables={reportsTimeSeriesVariables}
            render={({ props }) => {
              if (props && props.reportsTimeSeries) {
                return (
                  <ResponsiveContainer height={330} width='100%'>
                    <BarChart data={props.reportsTimeSeries} margin={{
                      top: 20, right: 50, bottom: 20, left: -10,
                    }}>
                      <CartesianGrid strokeDasharray='2 2' stroke='#0f181f'/>
                      <XAxis dataKey='date' stroke='#ffffff' interval={2} angle={-45} textAnchor='end' tickFormatter={md}/>
                      <YAxis stroke='#ffffff'/>
                      <Tooltip
                        cursor={{ fill: 'rgba(0, 0, 0, 0.2)', stroke: 'rgba(0, 0, 0, 0.2)', strokeWidth: 2 }}
                        contentStyle={{ backgroundColor: 'rgba(255, 255, 255, 0.1)', fontSize: 12, borderRadius: 10 }}
                        labelFormatter={md}
                      />
                      <Bar fill={Theme.palette.primary.main} dataKey='value' barSize={5}/>
                    </BarChart>
                  </ResponsiveContainer>
                );
              }
              if (props) {
                return (
                  <div style={{ textAlign: 'center', paddingTop: 140 }}>{t('No entities of this type has been found.')}</div>
                );
              }
              return (
                <div style={{ textAlign: 'center', paddingTop: 140 }}><CircularProgress size={40} thickness={2}/></div>
              );
            }}
          />
        </Paper>
      </div>
    );
  }
}

EntityReportsChart.propTypes = {
  entityId: PropTypes.string,
  classes: PropTypes.object,
  reportClass: PropTypes.string,
  t: PropTypes.func,
  md: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(EntityReportsChart);
