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
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import { QueryRenderer } from '../../../relay/environment';
import { now, yearsAgo } from '../../../utils/Time';
import Theme from '../../../components/Theme';
import inject18n from '../../../components/i18n';

const styles = theme => ({
  paper: {
    minHeight: 340,
    height: '100%',
    margin: '10px 0 0 0',
    padding: '0 0 10px 0',
    backgroundColor: theme.palette.paper.background,
    color: theme.palette.text.main,
    borderRadius: 6,
  },
});

const entityStixRelationsChartStixRelationTimeSeriesQuery = graphql`
    query EntityStixRelationsChartStixRelationTimeSeriesQuery($fromId: String, $entityTypes: [String] $relationType: String, $resolveRelationType: String, $resolveInferences: Boolean, $toTypes: [String], $field: String!, $operation: StatsOperation!, $startDate: DateTime!, $endDate: DateTime!, $interval: String!) {
        stixRelationsTimeSeries(fromId: $fromId, entityTypes: $entityTypes, relationType: $relationType, resolveRelationType: $resolveRelationType, resolveInferences: $resolveInferences, toTypes: $toTypes, field: $field, operation: $operation, startDate: $startDate, endDate: $endDate, interval: $interval) {
            date,
            value
        }
    }
`;

class EntityStixRelationsChart extends Component {
  render() {
    const {
      t,
      classes,
      entityId,
      toTypes,
      relationType,
      title,
      md,
      resolveInferences,
      entityTypes,
      resolveRelationType,
    } = this.props;
    const stixRelationsTimeSeriesVariables = {
      fromId: entityId || null,
      entityTypes: entityTypes || null,
      relationType,
      toTypes: toTypes || null,
      field: 'first_seen',
      operation: 'count',
      startDate: yearsAgo(3),
      endDate: now(),
      interval: 'month',
      resolveInferences,
      resolveRelationType,
    };
    return (
      <div style={{ height: '100%' }}>
        <Typography variant='h4' gutterBottom={true}>
          {title ? t(title) : t('Entity usage')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <QueryRenderer
            query={entityStixRelationsChartStixRelationTimeSeriesQuery}
            variables={stixRelationsTimeSeriesVariables}
            render={({ props }) => {
              if (props && props.stixRelationsTimeSeries) {
                return (
                  <ResponsiveContainer height={330} width='100%'>
                    <AreaChart data={props.stixRelationsTimeSeries} margin={{
                      top: 20, right: 50, bottom: 20, left: -10,
                    }}>
                      <CartesianGrid strokeDasharray='2 2' stroke='#0f181f'/>
                      <XAxis dataKey='date' stroke='#ffffff' interval={2} angle={-45} textAnchor='end' tickFormatter={md}/>
                      <YAxis stroke='#ffffff'/>
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

EntityStixRelationsChart.propTypes = {
  entityId: PropTypes.string,
  relationType: PropTypes.string,
  resolveInferences: PropTypes.bool,
  resolveRelationType: PropTypes.string,
  entityTypes: PropTypes.array,
  toTypes: PropTypes.array,
  title: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  md: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(EntityStixRelationsChart);
