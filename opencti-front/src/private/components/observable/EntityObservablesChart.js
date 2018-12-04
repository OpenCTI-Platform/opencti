import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import PieChart from 'recharts/lib/chart/PieChart';
import Pie from 'recharts/lib/polar/Pie';
import Cell from 'recharts/lib/component/Cell';
import ResponsiveContainer from 'recharts/lib/component/ResponsiveContainer';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
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

const colors = {
  'IPv4 Addresss': '#F44336',
  'IPv6 Addresss': '#009688',
  'MAC Adddress': '#03A9F4',
  Mutex: '#8BC34A',
  URL: '#FF9800',
};

class EntityObservablesChartComponent extends Component {
  constructor(props) {
    super(props);
    this.renderLabel = this.renderLabel.bind(this);
    this.state = {
      chartData: [
        { name: 'IPv4 Addresss', value: 8 },
        { name: 'IPv6 Addresss', value: 12 },
        { name: 'MAC Adddress', value: 45 },
        { name: 'Mutex', value: 42 },
        { name: 'URL', value: 12 },
      ],
    };
  }

  renderLabel(props) {
    const RADIAN = Math.PI / 180;
    const {
      cx, cy, midAngle, outerRadius,
      fill, payload, percent, value,
    } = props;
    const sin = Math.sin(-RADIAN * midAngle);
    const cos = Math.cos(-RADIAN * midAngle);
    const sx = cx + (outerRadius + 10) * cos;
    const sy = cy + (outerRadius + 10) * sin;
    const mx = cx + (outerRadius + 30) * cos;
    const my = cy + (outerRadius + 30) * sin;
    const ex = mx + (cos >= 0 ? 1 : -1) * 22;
    const ey = my;
    const textAnchor = cos >= 0 ? 'start' : 'end';

    return (
      <g>
        <path d={`M${sx},${sy}L${mx},${my}L${ex},${ey}`} stroke={fill} fill="none"/>
        <circle cx={ex} cy={ey} r={2} fill={fill} stroke="none"/>
        <text x={ex + (cos >= 0 ? 1 : -1) * 12} y={ey} textAnchor={textAnchor} fill="#ffffff" style={{ fontSize: 12 }}> { payload.name} ({value})</text>
        <text x={ex + (cos >= 0 ? 1 : -1) * 12} y={ey} dy={18} textAnchor={textAnchor} fill="#999999" style={{ fontSize: 12 }}>
          {` ${(percent * 100).toFixed(2)}%`}
        </text>
      </g>
    );
  }

  render() {
    const { t, classes } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant='h4' gutterBottom={true}>
          {t('Observables')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <ResponsiveContainer height={300} width='100%'>
            <PieChart margin={{
              top: 50, right: 12, bottom: 25, left: 0,
            }}>
              <Pie data={this.state.chartData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={60} outerRadius={80} fill="#82ca9d" label={this.renderLabel} labelLine={true}>
                {
                  this.state.chartData.map((entry, index) => <Cell key={index} fill={colors[entry.name]}/>)
                }
              </Pie>
            </PieChart>
          </ResponsiveContainer>
        </Paper>
      </div>
    );
  }
}

EntityObservablesChartComponent.propTypes = {
  observablesStats: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const EntityObservablesChart = createFragmentContainer(EntityObservablesChartComponent, {
  observablesStats: graphql`
      fragment EntityObservablesChart_observablesStats on Malware {
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
)(EntityObservablesChart);
