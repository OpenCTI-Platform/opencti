import React, { FunctionComponent } from 'react';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';
import { useTheme } from '@mui/styles';
import { AdministrativeArea_administrativeArea$data } from '@components/locations/administrative_areas/__generated__/AdministrativeArea_administrativeArea.graphql';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';

interface AdministrativeAreaDetailsProps {
  administrativeArea: AdministrativeArea_administrativeArea$data;
}

const AdministrativeAreaDetails: FunctionComponent<AdministrativeAreaDetailsProps> = ({ administrativeArea }) => {
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
            {administrativeArea.description && (
              <ExpandableMarkdown source={administrativeArea.description} limit={300} />
            )}
          </Grid>
        </Grid>
      </Paper>
    </div>
  );
};

export default AdministrativeAreaDetails;
