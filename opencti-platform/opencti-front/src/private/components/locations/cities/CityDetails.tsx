import React, { FunctionComponent } from 'react';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';
import { useTheme } from '@mui/styles';
import { City_city$data } from '@components/locations/cities/__generated__/City_city.graphql';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';

interface CityDetailsProps {
  city: City_city$data;
}

const CityDetails: FunctionComponent<CityDetailsProps> = ({ city }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

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
            {city.description && (
              <ExpandableMarkdown source={city.description} limit={300} />
            )}
          </Grid>
        </Grid>
      </Paper>
    </div>
  );
};

export default CityDetails;
