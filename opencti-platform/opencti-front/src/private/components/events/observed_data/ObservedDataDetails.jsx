import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import StixCoreObjectsDonut from '../../common/stix_core_objects/StixCoreObjectsDonut';
import inject18n from '../../../../components/i18n';

const styles = (theme) => ({
  paper: {
    marginTop: theme.spacing(1),
    padding: '15px',
    borderRadius: 4,
  },
});

class ObservedDataDetailsComponent extends Component {
  render() {
    const { t, fldt, classes, observedData } = this.props;
    const observablesDataSelection = [
      {
        attribute: 'entity_type',
        filters: {
          mode: 'and',
          filters: [
            {
              key: 'entity_type',
              values: 'Stix-Core-Object',
            },
            {
              key: 'regardingOf',
              values: [
                { key: 'id', values: [observedData.id] },
                { key: 'relationship_type', values: ['object'] },
              ],
            },
          ],
          filterGroups: [],
        },
      },
    ];
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Entity details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
          <Grid container={true} spacing={3}>
            <Grid item xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('First observed')}
              </Typography>
              {fldt(observedData.first_observed)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Number observed')}
              </Typography>
              {observedData.number_observed}
            </Grid>
            <Grid item xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Last observed')}
              </Typography>
              {fldt(observedData.last_observed)}
            </Grid>
          </Grid>
          <br />
          <StixCoreObjectsDonut
            dataSelection={observablesDataSelection}
            parameters={{ title: t('Observables distribution') }}
            variant="inEntity"
            height={300}
          />
        </Paper>
      </div>
    );
  }
}

ObservedDataDetailsComponent.propTypes = {
  observedData: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
  fld: PropTypes.func,
};

const ObservedDataDetails = createFragmentContainer(
  ObservedDataDetailsComponent,
  {
    observedData: graphql`
      fragment ObservedDataDetails_observedData on ObservedData {
        id
        first_observed
        last_observed
        number_observed
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(ObservedDataDetails);
