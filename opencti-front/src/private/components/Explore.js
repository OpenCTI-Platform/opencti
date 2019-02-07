/* eslint-disable no-nested-ternary */
// TODO Remove no-nested-ternary
import React, { Component } from 'react';
import { Link } from 'react-router-dom';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Card from '@material-ui/core/Card';
import CardActionArea from '@material-ui/core/CardActionArea';
import CardContent from '@material-ui/core/CardContent';
import Grid from '@material-ui/core/Grid';
import { BugReport } from '@material-ui/icons';
import {
  ChessKnight,
  LockPattern,
  TagMultiple,
  Target,
  SortAscending,
} from 'mdi-material-ui';
import inject18n from '../../components/i18n';

const styles = theme => ({
  card: {
    width: '100%',
    height: 150,
    marginBottom: 20,
    backgroundColor: theme.palette.paper.background,
    color: theme.palette.text.main,
    borderRadius: 6,
    position: 'relative',
    padding: 0,
  },
  actionArea: {
    height: '100%',
  },
  title: {
    marginTop: 5,
    textTransform: 'uppercase',
    color: theme.palette.primary.main,
    fontSize: 20,
  },
  title_disabled: {
    marginTop: 5,
    textTransform: 'uppercase',
    color: '#a0a0a0',
    fontSize: 20,
  },
  description: {
    paddingRight: 60,
    marginTop: 10,
    fontSize: 13,
    lineHeight: '1.7em',
  },
  icon: {
    position: 'absolute',
    top: 30,
    right: 20,
  },
});

class Explore extends Component {
  render() {
    const { t, classes } = this.props;
    return (
      <div>
        <Grid container={true} spacing={32}>
          <Grid item={true} xs={4}>
            <Card raised={true} classes={{ root: classes.card }}>
              <CardActionArea component={Link} to='/dashboard/explore/victimology' classes={{ root: classes.actionArea }}>
                <CardContent>
                  <div className={classes.title}>
                    {t('Victimology')}
                  </div>
                  <div className={classes.description}>
                    {t('Explore the victims and the targets of the dataset through space and time.')}
                  </div>
                  <div className={classes.icon}>
                    <Target fontSize='large'/>
                  </div>
                </CardContent>
              </CardActionArea>
            </Card>
          </Grid>
          <Grid item={true} xs={4}>
            <Card raised={true} classes={{ root: classes.card }}>
              <CardActionArea component={Link} to='/dashboard/explore/campaigns' classes={{ root: classes.actionArea }} disabled={true}>
                <CardContent>
                  <div className={classes.title_disabled}>
                    {t('Campaigns')}
                  </div>
                  <div className={classes.description}>
                    {t('Explore the attack campaigns of the dataset through time and involved entities.')}
                  </div>
                  <div className={classes.icon}>
                    <ChessKnight fontSize='large'/>
                  </div>
                </CardContent>
              </CardActionArea>
            </Card>
          </Grid>
          <Grid item={true} xs={4}>
            <Card raised={true} classes={{ root: classes.card }}>
              <CardActionArea component={Link} to='/dashboard/explore/ttp' classes={{ root: classes.actionArea }} disabled={true}>
                <CardContent>
                  <div className={classes.title_disabled}>
                    {t('Attack patterns')}
                  </div>
                  <div className={classes.description}>
                    {t('Explore the techniques, tactics and procedures of the dataset through time and entities who used its.')}
                  </div>
                  <div className={classes.icon}>
                    <LockPattern fontSize='large'/>
                  </div>
                </CardContent>
              </CardActionArea>
            </Card>
          </Grid>
        </Grid>
        <Grid container={true} spacing={32}>
          <Grid item={true} xs={4}>
            <Card raised={true} classes={{ root: classes.card }}>
              <CardActionArea component={Link} to='/dashboard/explore/killchains' classes={{ root: classes.actionArea }} disabled={true}>
                <CardContent>
                  <div className={classes.title_disabled}>
                    {t('Kill chains')}
                  </div>
                  <div className={classes.description}>
                    {t('Explore the kill chains of entities through time and other contextual information like campaigns or incidents.')}
                  </div>
                  <div className={classes.icon}>
                    <SortAscending fontSize='large'/>
                  </div>
                </CardContent>
              </CardActionArea>
            </Card>
          </Grid>
          <Grid item={true} xs={4}>
            <Card raised={true} classes={{ root: classes.card }}>
              <CardActionArea component={Link} to='/dashboard/explore/vulnerabilities' classes={{ root: classes.actionArea }} disabled={true}>
                <CardContent>
                  <div className={classes.title_disabled}>
                    {t('Vulnerabilities')}
                  </div>
                  <div className={classes.description}>
                    {t('Explore the vulnerabilities used by entities through time and kill chain phases.')}
                  </div>
                  <div className={classes.icon}>
                    <BugReport fontSize='large'/>
                  </div>
                </CardContent>
              </CardActionArea>
            </Card>
          </Grid>
          <Grid item={true} xs={4}>
            <Card raised={true} classes={{ root: classes.card }}>
              <CardActionArea component={Link} to='/dashboard/explore/observables' classes={{ root: classes.actionArea }} disabled={true}>
                <CardContent>
                  <div className={classes.title_disabled}>
                    {t('Observables')}
                  </div>
                  <div className={classes.description}>
                    {t('Explore the observables of the dataset though time to visualize clusters and correlations.')}
                  </div>
                  <div className={classes.icon}>
                    <TagMultiple fontSize='large'/>
                  </div>
                </CardContent>
              </CardActionArea>
            </Card>
          </Grid>
        </Grid>
      </div>
    );
  }
}

Explore.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(Explore);
