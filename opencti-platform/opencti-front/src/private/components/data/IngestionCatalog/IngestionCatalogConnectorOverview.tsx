import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import { Git } from 'mdi-material-ui';
import React from 'react';
import { useTheme } from '@mui/styles';
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';
import { IngestionConnector } from '@components/data/IngestionCatalog/IngestionCatalogCard';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';

const IngestionCatalogConnectorOverview = ({ connector }: { connector: IngestionConnector }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  return (
    <Grid container={true} spacing={3} style={{ marginBottom: 20 }}>

      <Grid item xs={8}>
        <Typography variant="h4" gutterBottom={true}>{t_i18n('Overview')}</Typography>
        <Paper
          style={{ marginTop: theme.spacing(1), padding: '15px', borderRadius: 4 }}
          variant="outlined"
        >
          {connector.description}
        </Paper>
      </Grid>

      <Grid item xs={4}>
        <Typography variant="h4" gutterBottom={true}>{t_i18n('Basic information')}</Typography>
        <Paper
          style={{ marginTop: theme.spacing(1), padding: '15px', borderRadius: 4 }}
          variant="outlined"
        >
          <Grid item xs={12}>
            <Button
              size="large"
              startIcon={<Git />}
              href={connector.source_code}
              target="blank"
              rel="noopener noreferrer"
            >
              {connector.title}
            </Button>
          </Grid>
          <Grid item xs={12}>
            <Typography variant="h3" gutterBottom={true} style={{ marginTop: 20 }}>{t_i18n('Last update')}</Typography>
            {connector.last_verified_date}
          </Grid>
        </Paper>
      </Grid>

    </Grid>
  );
};

export default IngestionCatalogConnectorOverview;
