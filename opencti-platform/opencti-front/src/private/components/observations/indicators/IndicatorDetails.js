import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../components/i18n';
import ItemScore from '../../../../components/ItemScore';
import IndicatorObservables from './IndicatorObservables';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
});

class IndicatorDetailsComponent extends Component {
  render() {
    const {
      t, fld, classes, indicator,
    } = this.props;
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Typography variant="h3" gutterBottom={true}>
            {t('Indicator pattern')}
          </Typography>
          <pre>{indicator.pattern}</pre>
          <Grid container={true} spacing={3} style={{ marginTop: 10 }}>
            <Grid item={true} xs={4}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Valid from')}
              </Typography>
              {fld(indicator.valid_from)}
            </Grid>
            <Grid item={true} xs={4}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Valid until')}
              </Typography>
              {fld(indicator.valid_until)}
            </Grid>
            <Grid item={true} xs={4}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Score')}
              </Typography>
              <ItemScore score={indicator.x_opencti_score} />
            </Grid>
          </Grid>
          <IndicatorObservables indicator={indicator} />
        </Paper>
      </div>
    );
  }
}

IndicatorDetailsComponent.propTypes = {
  indicator: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const IndicatorDetails = createFragmentContainer(IndicatorDetailsComponent, {
  indicator: graphql`
    fragment IndicatorDetails_indicator on Indicator {
      id
      pattern
      valid_from
      valid_until
      x_opencti_score
      x_opencti_detection
      creator {
        id
        name
      }
      objectLabel {
        edges {
          node {
            id
            value
            color
          }
        }
      }
      ...IndicatorObservables_indicator
    }
  `,
});

export default compose(inject18n, withStyles(styles))(IndicatorDetails);
