import React, { FunctionComponent } from 'react';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';
import { useTheme } from '@mui/styles';
import { LocationDetails_location$key } from '@components/locations/__generated__/LocationDetails_location.graphql';
import { graphql, useFragment } from 'react-relay';
import ExpandableMarkdown from '../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';

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
  const theme = useTheme<Theme>();
  const location = useFragment(locationDetailsFragment, locationData);

  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Details')}
      </Typography>
      <Paper style={{
        marginTop: theme.spacing(1),
        padding: '15px',
        borderRadius: 4,
      }}
        className={'paper-for-grid'} variant="outlined"
      >
        <Grid container={true} spacing={3}>
          <Grid item xs={12}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Description')}
            </Typography>
            <ExpandableMarkdown source={location.description} limit={300} />
          </Grid>
        </Grid>
      </Paper>
    </div>
  );
};

export default LocationDetails;
