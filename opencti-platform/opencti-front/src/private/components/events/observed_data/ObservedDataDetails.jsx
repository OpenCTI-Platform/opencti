import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import Grid from '@mui/material/Grid';
import Card from '@common/card/Card';
import StixCoreObjectsDonut from '../../common/stix_core_objects/StixCoreObjectsDonut';
import inject18n from '../../../../components/i18n';
import Label from '../../../../components/common/label/Label';

class ObservedDataDetailsComponent extends Component {
  render() {
    const { t, fldt, observedData } = this.props;
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
      <div style={{ height: '100%' }} data-testid="observed-data-details-page">
        <Card title={t('Entity details')}>
          <Grid container={true} spacing={2} sx={{ mb: 2 }}>
            <Grid item xs={6}>
              <Label>
                {t('First observed')}
              </Label>
              {fldt(observedData.first_observed)}
              <Label
                sx={{ marginTop: 2 }}
              >
                {t('Number observed')}
              </Label>
              {observedData.number_observed}
            </Grid>
            <Grid item xs={6}>
              <Label>
                {t('Last observed')}
              </Label>
              {fldt(observedData.last_observed)}
            </Grid>
          </Grid>
          <StixCoreObjectsDonut
            dataSelection={observablesDataSelection}
            parameters={{ title: t('Observables distribution') }}
            variant="inEntity"
            height={300}
          />
        </Card>
      </div>
    );
  }
}

ObservedDataDetailsComponent.propTypes = {
  observedData: PropTypes.object,
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

export default compose(inject18n)(ObservedDataDetails);
