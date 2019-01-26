import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import ResponsiveContainer from 'recharts/lib/component/ResponsiveContainer';
import RadarChart from 'recharts/lib/chart/RadarChart';
import PolarGrid from 'recharts/lib/polar/PolarGrid';
import PolarAngleAxis from 'recharts/lib/polar/PolarAngleAxis';
import PolarRadiusAxis from 'recharts/lib/polar/PolarRadiusAxis';
import Radar from 'recharts/lib/polar/Radar';
import Legend from 'recharts/lib/component/Legend';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../components/i18n';
import Theme from '../../../components/Theme';

const styles = theme => ({
  paper: {
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '30px 0 0 0',
    backgroundColor: theme.palette.paper.background,
    color: theme.palette.text.main,
    borderRadius: 6,
  },
});

class EntityKillChainPhasesChartComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      chartData: [
        { name: 'privilege-escalation', value: 8 },
        { name: 'credential-access', value: 12 },
        { name: 'defense-evasion', value: 5 },
        { name: 'lateral-movement', value: 7 },
        { name: 'fdfds-movement', value: 7 },
      ],
    };
  }

  render() {
    const { t, classes } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant='h4' gutterBottom={true}>
          {t('Kill chain phases')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <ResponsiveContainer height={300} width='100%'>
            <RadarChart outerRadius={110} data={this.state.chartData}>
              <PolarGrid/>
              <PolarAngleAxis dataKey='name' stroke='#ffffff'/>
              <PolarRadiusAxis/>
              <Radar name="Mike" dataKey="value" stroke="#8884d8" fill={Theme.palette.primary.main} fillOpacity={0.6}/>
            </RadarChart>
          </ResponsiveContainer>
        </Paper>
      </div>
    );
  }
}

EntityKillChainPhasesChartComponent.propTypes = {
  observablesStats: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const EntityKillChainPhasesChart = createFragmentContainer(EntityKillChainPhasesChartComponent, {
  observablesStats: graphql`
      fragment EntityKillChainPhasesChart_observablesStats on Malware {
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
)(EntityKillChainPhasesChart);
