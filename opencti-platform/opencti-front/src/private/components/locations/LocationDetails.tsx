import React, { FunctionComponent } from 'react';
import { LocationDetails_location$key } from '@components/locations/__generated__/LocationDetails_location.graphql';
import { graphql, useFragment } from 'react-relay';
import ExpandableMarkdown from '../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../components/i18n';
import Card from '../../../components/common/card/Card';
import Label from '../../../components/common/label/Label';
import Grid from '@mui/material/Grid';
import CustomFieldValuesDisplay from '@components/common/custom_fields/CustomFieldValuesDisplay';

const locationDetailsFragment = graphql`
  fragment LocationDetails_location on Location {
    id
    entity_type
    description
    ... on StixDomainObject {
      customFieldValues {
        ...CustomFieldValuesDisplay_values @relay(mask: false)
      }
    }
  }
`;

interface LocationDetailsProps {
  locationData: LocationDetails_location$key;
}

const LocationDetails: FunctionComponent<LocationDetailsProps> = ({ locationData }) => {
  const { t_i18n } = useFormatter();
  const location = useFragment(locationDetailsFragment, locationData);

  return (
    <div style={{ height: '100%' }}>
      <Card title={t_i18n('Details')}>
        <Grid container={true} spacing={3}>
          <Grid item xs={12}>
            <Label>
              {t_i18n('Description')}
            </Label>
            <ExpandableMarkdown source={location.description} limit={1400} />
          </Grid>
          <CustomFieldValuesDisplay entityType={location.entity_type} values={location.customFieldValues ?? []} />
        </Grid>
      </Card>
    </div>
  );
};

export default LocationDetails;
