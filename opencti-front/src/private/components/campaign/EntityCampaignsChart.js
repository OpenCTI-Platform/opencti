import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import LineChart from 'recharts/lib/chart/LineChart';
import ResponsiveContainer from 'recharts/lib/component/ResponsiveContainer';
import CartesianGrid from 'recharts/lib/cartesian/CartesianGrid';
import Line from 'recharts/lib/cartesian/Line';
import XAxis from 'recharts/lib/cartesian/XAxis';
import YAxis from 'recharts/lib/cartesian/YAxis';
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
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: 0,
    backgroundColor: theme.palette.paper.background,
    color: theme.palette.text.main,
    borderRadius: 6,
  },
});

const entityCampaignsChartCampaignsTimeSeriesQuery = graphql`
    query EntityCampaignsChartCampaignsTimeSeriesQuery($objectId: String, $field: String!, $operation: StatsOperation!, $startDate: DateTime!, $endDate: DateTime!, $interval: String!) {
        campaignsTimeSeries(objectId: $objectId, field: $field, operation: $operation, startDate: $startDate, endDate: $endDate, interval: $interval) {
            date,
            value
        }
    }
`;

class EntityCampaignsChart extends Component {
  render() {
    const {
      t, md, classes, entityId,
    } = this.props;
    const campaignsTimeSeriesVariables = {
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
          {t('Campaigns')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <QueryRenderer
            query={entityCampaignsChartCampaignsTimeSeriesQuery}
            variables={campaignsTimeSeriesVariables}
            render={({ props }) => {
              if (props && props.campaignsTimeSeries) {
                return (
                  <ResponsiveContainer height={330} width='100%'>
                    <LineChart data={props.campaignsTimeSeries} margin={{
                      top: 20, right: 50, bottom: 20, left: -10,
                    }}>
                      <CartesianGrid strokeDasharray='2 2' stroke='#0f181f'/>
                      <XAxis dataKey='date' stroke='#ffffff' interval={2} angle={-45} textAnchor='end' tickFormatter={md}/>
                      <YAxis stroke='#ffffff'/>
                      <Line type='monotone' stroke={Theme.palette.primary.main} dataKey='value'/>
                    </LineChart>
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

EntityCampaignsChart.propTypes = {
  entityId: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(EntityCampaignsChart);
