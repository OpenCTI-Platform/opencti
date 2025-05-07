import React, { FunctionComponent } from 'react';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';
import { useTheme } from '@mui/styles';
import { Region_region$data } from '@components/locations/regions/__generated__/Region_region.graphql';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';

interface RegionDetailsProps {
  region: Region_region$data;
}

const RegionDetails: FunctionComponent<RegionDetailsProps> = ({ region }) => {
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
            {region.description && (
              <ExpandableMarkdown source={region.description} limit={300} />
            )}
          </Grid>
        </Grid>
      </Paper>
    </div>
  );
};

export default RegionDetails;
