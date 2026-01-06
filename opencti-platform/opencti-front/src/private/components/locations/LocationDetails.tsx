import React, { FunctionComponent } from 'react';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import { LocationDetails_location$key } from '@components/locations/__generated__/LocationDetails_location.graphql';
import { graphql, useFragment } from 'react-relay';
import ExpandableMarkdown from '../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../components/i18n';
import Card from '../../../components/common/card/Card';

const locationDetailsFragment = graphql`
  fragment LocationDetails_location on Location {
    id
    description
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
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Description')}
            </Typography>
            <ExpandableMarkdown source={location.description} limit={300} />
          </Grid>
        </Grid>
      </Card>
    </div>
  );
};

export default LocationDetails;
