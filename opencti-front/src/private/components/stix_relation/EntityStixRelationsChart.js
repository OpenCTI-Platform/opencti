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
import CircularProgress from '@material-ui/core/CircularProgress';
import Paper from '@material-ui/core/Paper';
import Chip from '@material-ui/core/Chip';
import Typography from '@material-ui/core/Typography';
import { QueryRenderer } from '../../../relay/environment';
import { monthsAgo, now } from '../../../utils/Time';
import Theme from '../../../components/Theme';
import inject18n from '../../../components/i18n';

const styles = theme => ({
  paper: {
    minHeight: 340,
    height: '100%',
    margin: '4px 0 0 0',
    backgroundColor: theme.palette.paper.background,
    color: theme.palette.text.main,
    borderRadius: 6,
  },
  chip: {
    fontSize: 10,
    height: 20,
    marginLeft: 10,
  },
});

const entityStixRelationsChartStixRelationTimeSeriesQuery = graphql`
    query EntityStixRelationsChartStixRelationTimeSeriesQuery($fromId: String, $entityTypes: [String] $relationType: String, $resolveInferences: Boolean, $resolveRelationType: String, $resolveRelationRole: String, $resolveRelationToTypes: [String], $resolveViaTypes: [EntityRelation], $toTypes: [String], $field: String!, $operation: StatsOperation!, $startDate: DateTime!, $endDate: DateTime!, $interval: String!) {
        stixRelationsTimeSeries(fromId: $fromId, entityTypes: $entityTypes, relationType: $relationType, resolveInferences: $resolveInferences, resolveRelationType: $resolveRelationType, resolveRelationRole: $resolveRelationRole, resolveRelationToTypes: $resolveRelationToTypes, resolveViaTypes: $resolveViaTypes, toTypes: $toTypes, field: $field, operation: $operation, startDate: $startDate, endDate: $endDate, interval: $interval) {
            date,
            value
        }
    }
`;

class EntityStixRelationsChart extends Component {
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
      resolveRelationRole,
      resolveRelationToTypes,
      resolveViaTypes,
    } = this.props;
    const stixRelationsTimeSeriesVariables = {
      fromId: entityId || null,
      entityTypes: entityTypes || null,
      relationType,
      toTypes: toTypes || null,
      field: 'first_seen',
      operation: 'count',
      startDate: monthsAgo(this.state.period),
      endDate: now(),
      interval: 'month',
      resolveInferences,
      resolveRelationType,
      resolveRelationRole,
      resolveRelationToTypes,
      resolveViaTypes,
    };
    return (
      <div style={{ height: '100%' }}>
        <Typography variant='h4' gutterBottom={true} style={{ float: 'left' }}>
          {title ? t(title) : t('Entity usage')}
        </Typography>
        <div style={{ float: 'right', marginTop: -6 }}>
          <Chip classes={{ root: classes.chip }} style={{ backgroundColor: this.state.period === 12 ? '#795548' : '#757575' }} label='12M' component='button' onClick={this.changePeriod.bind(this, 12)}/>
          <Chip classes={{ root: classes.chip }} style={{ backgroundColor: this.state.period === 24 ? '#795548' : '#757575' }} label='24M' component='button' onClick={this.changePeriod.bind(this, 24)}/>
          <Chip classes={{ root: classes.chip }} style={{ backgroundColor: this.state.period === 36 ? '#795548' : '#757575' }} label='36M' component='button' onClick={this.changePeriod.bind(this, 36)}/>
        </div>
        <div className='clearfix'/>
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
                      <XAxis dataKey='date' stroke='#ffffff' interval={this.state.interval} angle={-45} textAnchor='end' tickFormatter={md}/>
                      <YAxis stroke='#ffffff'/>
                      <Area type='monotone' stroke={Theme.palette.primary.main} dataKey='value'/>
                    </AreaChart>
                  </ResponsiveContainer>
                );
              }
              if (props) {
                return (
                  <div style={{ display: 'table', height: '100%', width: '100%' }}>
                    <span style={{ display: 'table-cell', verticalAlign: 'middle', textAlign: 'center' }}>
                      {t('No entities of this type has been found.')}
                    </span>
                  </div>
                );
              }
              return (
                <div style={{ display: 'table', height: '100%', width: '100%' }}>
                    <span style={{ display: 'table-cell', verticalAlign: 'middle', textAlign: 'center' }}>
                      <CircularProgress size={40} thickness={2}/>
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

EntityStixRelationsChart.propTypes = {
  entityId: PropTypes.string,
  relationType: PropTypes.string,
  resolveInferences: PropTypes.bool,
  resolveRelationType: PropTypes.string,
  resolveRelationRole: PropTypes.string,
  resolveRelationToTypes: PropTypes.array,
  resolveViaTypes: PropTypes.array,
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
