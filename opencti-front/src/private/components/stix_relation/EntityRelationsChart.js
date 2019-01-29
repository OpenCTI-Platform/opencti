import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import PieChart from 'recharts/lib/chart/PieChart';
import Pie from 'recharts/lib/polar/Pie';
import Cell from 'recharts/lib/component/Cell';
import Legend from 'recharts/lib/component/Legend';
import ResponsiveContainer from 'recharts/lib/component/ResponsiveContainer';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../components/i18n';
import { itemColor } from '../../../utils/Colors';

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
const RADIAN = Math.PI / 180;
const renderCustomizedLabel = ({
  cx, cy, midAngle, innerRadius, outerRadius, percent, index,
}) => {
  const radius = innerRadius + (outerRadius - innerRadius) * 0.5;
  const x = cx + radius * Math.cos(-midAngle * RADIAN);
  const y = cy + radius * Math.sin(-midAngle * RADIAN);

  return (
    <text x={x} y={y} fill="white" textAnchor={x > cx ? 'start' : 'end'} 	dominantBaseline="central">
      {`${(percent * 100).toFixed(0)}%`}
    </text>
  );
};

class EntityRelationsChartComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      chartData: [
        { name: 'intrusion-set', value: 8 },
        { name: 'campaign', value: 12 },
        { name: 'incident', value: 45 },
        { name: 'malware', value: 42 },
        { name: 'tool', value: 12 },
      ],
    };
  }

  render() {
    const { t, classes } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant='h4' gutterBottom={true}>
          {t('Entities types')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <ResponsiveContainer height={300} width='100%'>
            <PieChart margin={{
              top: 50, right: 12, bottom: 25, left: 0,
            }}>
              <Pie data={this.state.chartData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={100} fill="#82ca9d" label={renderCustomizedLabel} labelLine={false}>
                {
                  this.state.chartData.map((entry, index) => <Cell key={index} fill={itemColor(entry.name)}/>)
                }
              </Pie>
              <Legend verticalAlign='bottom' wrapperStyle={{ paddingTop: 20 }} />
            </PieChart>
          </ResponsiveContainer>
        </Paper>
      </div>
    );
  }
}

EntityRelationsChartComponent.propTypes = {
  observablesStats: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const EntityRelationsChart = createFragmentContainer(EntityRelationsChartComponent, {
  observablesStats: graphql`
      fragment EntityRelationsChart_observablesStats on Malware {
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
)(EntityRelationsChart);
