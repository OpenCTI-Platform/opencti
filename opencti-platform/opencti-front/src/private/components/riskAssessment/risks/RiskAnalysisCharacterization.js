/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose,
  pathOr,
  path,
  mergeAll,
  pipe,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Grid from '@material-ui/core/Grid';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../components/i18n';

const styles = () => ({
  paper: {
    height: '506px',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '0 24px',
    borderRadius: 6,
    overflowY: 'scroll',
  },
  header: {
    borderBottom: '1px solid white',
    padding: '22px 0 13px 0',
  },
  headerText: {
    paddingLeft: '16px',
    textTransform: 'capitalize',
  },
  tableText: {
    padding: '20px 0 20px 16px',
    textTransform: 'none',
  },
});

class RiskAnalysisCharacterizationComponent extends Component {
  render() {
    const {
      t, classes, risk,
    } = this.props;
    const riskAnalysisCharacterization = pipe(
      pathOr([], ['characterizations']),
    )(risk);
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Characterization')}
        </Typography>
        <Paper className={classes.paper} elevation={2}>
          <Grid container={true} className={classes.header}>
            <Grid item={true} xs={4}>
              <Typography
                variant="h2"
                gutterBottom={true}
                className={classes.headerText}
              >
                {t('Name')}
              </Typography>
            </Grid>
            <Grid item={true} xs={4}>
              <Typography
                variant="h2"
                gutterBottom={true}
                className={classes.headerText}
              >
                {t('Value')}
              </Typography>
            </Grid>
            <Grid item={true} xs={4}>
              <Typography
                variant="h2"
                gutterBottom={true}
                className={classes.headerText}
              >
                {t('Detection Source')}
              </Typography>
            </Grid>
          </Grid>
          {riskAnalysisCharacterization.map((characterization) =>
            characterization.facets.map((characterizationData) => {
              const DetectionSource = pipe(
                pathOr([], ['origins']),
                mergeAll,
                path(['origin_actors']),
                mergeAll,
              )(characterization);
              return (
                <Grid key={characterizationData.id} container={true}
                  style={{ borderBottom: '1px solid grey' }}>
                  <Grid item={true} xs={4}>
                    <Typography
                      variant="h2"
                      gutterBottom={true}
                      className={classes.tableText}
                    >
                      {characterizationData.facet_name && t(characterizationData.facet_name)}
                    </Typography>
                  </Grid>
                  <Grid item={true} xs={4}>
                    <Typography
                      variant="h2"
                      gutterBottom={true}
                      className={classes.tableText}
                    >
                      {characterizationData?.facet_value && t(characterizationData?.facet_value)}
                    </Typography>
                  </Grid>
                  <Grid item={true} xs={4}>
                    <Typography
                      variant="h2"
                      gutterBottom={true}
                      className={classes.tableText}
                    >
                      {DetectionSource?.actor_ref && t(DetectionSource?.actor_ref?.name)}
                    </Typography>
                  </Grid>
                </Grid>
              );
            }))}
        </Paper>
      </div>
    );
  }
}

RiskAnalysisCharacterizationComponent.propTypes = {
  risk: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(RiskAnalysisCharacterizationComponent);
