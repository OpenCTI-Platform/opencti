import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose,
  pathOr,
  map,
  path,
  mergeAll,
  pipe,
} from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Table from '@material-ui/core/Table';
import LaunchIcon from '@material-ui/icons/Launch';
import Grid from '@material-ui/core/Grid';
import Badge from '@material-ui/core/Badge';
import Avatar from '@material-ui/core/Avatar';
import Chip from '@material-ui/core/Chip';
import { InformationOutline, Information } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../components/i18n';
import ItemAuthor from '../../../../components/ItemAuthor';
import ItemMarking from '../../../../components/ItemMarking';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';

const styles = (theme) => ({
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
    textTransform: 'capitalize',
  },
});

class RiskAnalysisCharacterizationComponent extends Component {
  render() {
    const {
      t, fldt, classes, risk,
    } = this.props;
    const riskAnalysisCharacterization = pipe(
      pathOr([], ['characterizations']),
      mergeAll,
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
          {riskAnalysisCharacterization.facets.map((characterizationData) => {
            const DetectionSource = pipe(
              pathOr([], ['origins']),
              mergeAll,
              path(['origin_actors']),
              mergeAll,
            )(riskAnalysisCharacterization);
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
                    {DetectionSource.actor_ref.name && t(DetectionSource.actor_ref.name)}
                  </Typography>
                </Grid>
              </Grid>
            );
          })}
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
