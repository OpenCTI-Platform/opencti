import React, { Component } from 'react';
import { withStyles } from '@material-ui/core/styles';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import Card from '@material-ui/core/Card';
import Grid from '@material-ui/core/Grid';
import CardContent from '@material-ui/core/CardContent';
import {
  ArrowUpward, Assignment, Layers, DeviceHub,
} from '@material-ui/icons';
import {
  Database,
} from 'mdi-material-ui';
import BarChart from 'recharts/lib/chart/BarChart';
import ResponsiveContainer from 'recharts/lib/component/ResponsiveContainer';
import Bar from 'recharts/lib/cartesian/Bar';
import XAxis from 'recharts/lib/cartesian/XAxis';
import YAxis from 'recharts/lib/cartesian/YAxis';
import Theme from '../../components/Theme';
import inject18n from '../../components/i18n';

const styles = theme => ({
  card: {
    width: '100%',
    height: '100%',
    backgroundColor: theme.palette.paper.background,
    color: theme.palette.text.main,
    borderRadius: 6,
    position: 'relative',
  },
  number: {
    float: 'left',
    color: theme.palette.primary.main,
    fontSize: 40,
  },
  diff: {
    float: 'left',
    margin: '13px 0 0 10px',
    fontSize: 13,
  },
  diffIcon: {
    float: 'left',
    color: '#4caf50',
  },
  diffNumber: {
    marginTop: 6,
    float: 'left',
    color: '#4caf50',
  },
  diffDescription: {
    margin: '6px 0 0 10px',
    float: 'left',
  },
  title: {
    marginTop: 5,
    textTransform: 'uppercase',
    fontSize: 12,
  },
  icon: {
    position: 'absolute',
    top: 30,
    right: 20,
  },
  graphContainer: {
    width: '100%',
    margin: '20px 0 0 -30px',
  },
});

class Dashboard extends Component {
  constructor(props) {
    super(props);
    this.state = {
      chartData: [
        { date: '2017-11-01', number: 8 },
        { date: '2017-12-01', number: 12 },
        { date: '2018-01-01', number: 45 },
        { date: '2018-02-01', number: 42 },
        { date: '2018-03-01', number: 12 },
        { date: '2018-04-01', number: 69 },
        { date: '2018-05-01', number: 45 },
        { date: '2018-06-01', number: 42 },
        { date: '2018-07-01', number: 15 },
        { date: '2018-08-01', number: 25 },
        { date: '2018-09-01', number: 58 },
        { date: '2018-10-01', number: 45 },
      ],
    };
  }

  render() {
    const { t, nsd, classes } = this.props;
    return (
      <Grid container={true}>
        <Grid container={true} xs={6} spacing={16}>
          <Grid item={true} xs={6}>
            <Card raised={true} classes={{ root: classes.card }}>
              <CardContent>
                <div className={classes.number}>
                  5 456
                </div>
                <div className={classes.diff}>
                  <ArrowUpward color='inherit' classes={{ root: classes.diffIcon }}/>
                  <div className={classes.diffNumber}>
                    5 123
                  </div>
                  <div className={classes.diffDescription}>
                    ({t('last 24h')})
                  </div>
                </div>
                <div className='clearfix'/>
                <div className={classes.title}>
                  {t('Total entities')}
                </div>
                <div className={classes.icon}>
                  <Database color='inherit' fontSize='large'/>
                </div>
              </CardContent>
            </Card>
          </Grid>
          <Grid item={true} xs={6}>
            <Card raised={true} classes={{ root: classes.card }}>
              <CardContent>
                <div className={classes.number}>
                  12 568
                </div>
                <div className={classes.diff}>
                  <ArrowUpward color='inherit' classes={{ root: classes.diffIcon }}/>
                  <div className={classes.diffNumber}>
                    889
                  </div>
                  <div className={classes.diffDescription}>
                    ({t('last 24h')})
                  </div>
                </div>
                <div className='clearfix'/>
                <div className={classes.title}>
                  {t('Total observables')}
                </div>
                <div className={classes.icon}>
                  <Layers color='inherit' fontSize='large'/>
                </div>
              </CardContent>
            </Card>
          </Grid>
          <Grid item={true} xs={6}>
            <Card raised={true} classes={{ root: classes.card }}>
              <CardContent>
                <div className={classes.number}>
                  849
                </div>
                <div className={classes.diff}>
                  <ArrowUpward color='inherit' classes={{ root: classes.diffIcon }}/>
                  <div className={classes.diffNumber}>
                    5
                  </div>
                  <div className={classes.diffDescription}>
                    ({t('last 24h')})
                  </div>
                </div>
                <div className='clearfix'/>
                <div className={classes.title}>
                  {t('Total reports')}
                </div>
                <div className={classes.icon}>
                  <Assignment color='inherit' fontSize='large'/>
                </div>
              </CardContent>
            </Card>
          </Grid>
          <Grid item={true} xs={6}>
            <Card raised={true} classes={{ root: classes.card }}>
              <CardContent>
                <div className={classes.number}>
                  156
                </div>
                <div className={classes.diff}>
                  <ArrowUpward color='inherit' classes={{ root: classes.diffIcon }}/>
                  <div className={classes.diffNumber}>
                    8
                  </div>
                  <div className={classes.diffDescription}>
                    ({t('last 24h')})
                  </div>
                </div>
                <div className='clearfix'/>
                <div className={classes.title}>
                  {t('Total investigations')}
                </div>
                <div className={classes.icon}>
                  <DeviceHub color='inherit' fontSize='large'/>
                </div>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
        <Grid container={true} xs={6}>
          <Grid item={true} xs={12} spacing={16}>
            <Card raised={true} classes={{ root: classes.card }} style={{ marginLeft: 16 }}>
              <CardContent>
                <div className={classes.title}>
                  {t('Ingested entities')}
                </div>
                <div className={classes.graphContainer}>
                  <ResponsiveContainer height={180} width='100%'>
                    <BarChart data={this.state.chartData} margin={{
                      top: 5, right: 5, bottom: 25, left: 5,
                    }}>
                      <XAxis dataKey='date' stroke='#ffffff' interval={0} angle={-45} textAnchor='end' tickFormatter={nsd}/>
                      <YAxis stroke='#ffffff'/>
                      <Bar fill={Theme.palette.primary.main} dataKey='number' barSize={10}/>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </Grid>
    );
  }
}

Dashboard.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  nsd: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(Dashboard);
