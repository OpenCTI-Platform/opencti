import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import {Launch} from 'mdi-material-ui';
import React from 'react';
import {useTheme} from '@mui/styles';
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';
import {IngestionConnector} from '@components/data/IngestionCatalog';
import {LibraryBooksOutlined} from '@mui/icons-material';
import type {Theme} from '../../../../components/Theme';
import {useFormatter} from '../../../../components/i18n';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';

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
          <MarkdownDisplay content={connector.description} />
        </Paper>
      </Grid>

      <Grid item xs={4}>
        <Typography variant="h4" gutterBottom={true}>{t_i18n('Basic information')}</Typography>
        <Paper
          style={{ marginTop: theme.spacing(1), padding: '15px', borderRadius: 4 }}
          variant="outlined"
        >
          <Grid item xs={12}>
            <Typography variant="h3" gutterBottom={true}>{t_i18n('Integration documentation and code')}</Typography>
            <Button
              size="large"
              startIcon={<LibraryBooksOutlined />}
              href={connector.source_code}
              target="blank"
              rel="noopener noreferrer"
            >
              {connector.title}
            </Button>
          </Grid>
          <Grid item xs={12} style={{ marginTop: 20 }}>
            <Typography variant="h3" gutterBottom={true}>{t_i18n('Visit the vendor\'s page to learn more and get in touch')}</Typography>
            <Button
              size="large"
              startIcon={<Launch />}
              href={connector.subscription_link}
              target="blank"
              rel="noopener noreferrer"
              disabled={!connector.subscription_link}
            >
              {t_i18n('Vendor contact')}
            </Button>
          </Grid>
          <Grid item xs={12} style={{ marginTop: 20 }}>
            <Typography variant="h3" gutterBottom={true}>{t_i18n('Last verified')}</Typography>
            {connector.last_verified_date || '-' }
          </Grid>
        </Paper>
      </Grid>

    </Grid>
  );
};

export default IngestionCatalogConnectorOverview;
