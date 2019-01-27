import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import LineChart from 'recharts/lib/chart/LineChart';
import ResponsiveContainer from 'recharts/lib/component/ResponsiveContainer';
import CartesianGrid from 'recharts/lib/cartesian/CartesianGrid';
import Line from 'recharts/lib/cartesian/Line';
import XAxis from 'recharts/lib/cartesian/XAxis';
import YAxis from 'recharts/lib/cartesian/YAxis';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
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

class EntityReportsChartComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      chartData: [
        { date: '2018-04', value: 0 },
        { date: '2018-05', value: 2 },
        { date: '2018-06', value: 4 },
        { date: '2018-07', value: 2 },
        { date: '2018-08', value: 4 },
        { date: '2018-09', value: 3 },
        { date: '2018-10', value: 2 },
        { date: '2018-11', value: 4 },
        { date: '2018-12', value: 5 },
      ],
    };
  }

  render() {
    const { t, classes } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant='h4' gutterBottom={true}>
          {t('Campaigns')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <ResponsiveContainer height={330} width='100%'>
            <LineChart data={this.state.chartData} margin={{
              top: 20, right: 50, bottom: 20, left: -10,
            }}>
              <CartesianGrid strokeDasharray='3 3'/>
              <XAxis dataKey='date' stroke='#ffffff' interval={0} angle={-45} textAnchor='end'/>
              <YAxis stroke='#ffffff'/>
              <Line type='monotone' stroke={Theme.palette.primary.main} dataKey='value'/>
            </LineChart>
          </ResponsiveContainer>
        </Paper>
      </div>
    );
  }
}

EntityReportsChartComponent.propTypes = {
  observablesStats: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const EntityReportsChart = createFragmentContainer(EntityReportsChartComponent, {
  observablesStats: graphql`
      fragment EntityCampaignsChart_observablesStats on Malware {
          id,
          name,
          description,
          created,
          modified
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(EntityReportsChart);
