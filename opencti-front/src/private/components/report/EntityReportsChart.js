import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import BarChart from 'recharts/lib/chart/BarChart';
import ResponsiveContainer from 'recharts/lib/component/ResponsiveContainer';
import CartesianGrid from 'recharts/lib/cartesian/CartesianGrid';
import Bar from 'recharts/lib/cartesian/Bar';
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
        { date: '2018-08', value: 8 },
        { date: '2018-09', value: 12 },
        { date: '2018-10', value: 45 },
        { date: '2018-11', value: 42 },
        { date: '2018-12', value: 12 },
      ],
    };
  }

  render() {
    const { t, classes } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant='h4' gutterBottom={true}>
          {t('Reports')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <ResponsiveContainer height={330} width='100%'>
            <BarChart data={this.state.chartData} margin={{
              top: 20, right: 50, bottom: 20, left: -10,
            }}>
              <CartesianGrid strokeDasharray='3 3'/>
              <XAxis dataKey='date' stroke='#ffffff' interval={0} angle={-45} textAnchor='end'/>
              <YAxis stroke='#ffffff'/>
              <Bar fill={Theme.palette.primary.main} dataKey='value' barSize={5}/>
            </BarChart>
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
      fragment EntityReportsChart_observablesStats on Malware {
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
