import React from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import Grid from '@mui/material/Grid';
import Card from '@common/card/Card';
import StixCoreObjectsDonut from '../../common/stix_core_objects/StixCoreObjectsDonut';
import { useFormatter } from '../../../../components/i18n';
import Label from '../../../../components/common/label/Label';

const ObservedDataDetailsComponent = (props) => {
  const { t_i18n, fldt } = useFormatter();
  const { observedData } = props;
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

  const config = {
    startDate: undefined,
    endDate: undefined,
  };

  return (
    <div style={{ height: '100%' }} data-testid="observed-data-details-page">
      <Card title={t_i18n('Entity details')}>
        <Grid container={true} spacing={2} sx={{ mb: 2 }}>
          <Grid item xs={6}>
            <Label>
              {t_i18n('First observed')}
            </Label>
            {fldt(observedData.first_observed)}
            <Label
              sx={{ marginTop: 2 }}
            >
              {t_i18n('Number observed')}
            </Label>
            {observedData.number_observed}
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Last observed')}
            </Label>
            {fldt(observedData.last_observed)}
          </Grid>
        </Grid>
        <StixCoreObjectsDonut
          dataSelection={observablesDataSelection}
          parameters={{ title: t_i18n('Observables distribution') }}
          variant="inEntity"
          height={300}
          config={config}
        />
      </Card>
    </div>
  );
};

ObservedDataDetailsComponent.propTypes = {
  observedData: PropTypes.object,
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

export default ObservedDataDetails;
