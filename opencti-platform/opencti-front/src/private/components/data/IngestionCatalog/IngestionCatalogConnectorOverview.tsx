import Typography from '@mui/material/Typography';
import Button from '@common/button/Button';
import { Launch } from 'mdi-material-ui';
import Grid from '@mui/material/Grid2';
import { IngestionConnector } from '@components/data/IngestionCatalog';
import { LibraryBooksOutlined } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import Card from '../../../../components/common/card/Card';

const IngestionCatalogConnectorOverview = ({ connector }: { connector: IngestionConnector }) => {
  const { t_i18n } = useFormatter();

  return (
    <Grid container spacing={3} sx={{ marginBottom: 20 }}>
      <Grid size={{ xs: 12, md: 8 }}>
        <Card title={t_i18n('Overview')}>
          <MarkdownDisplay content={connector.description} />
        </Card>
      </Grid>

      <Grid size={{ xs: 12, md: 4 }}>
        <Card title={t_i18n('Basic information')}>
          <Grid container spacing={2.5}>
            <Grid size={12}>
              <Typography variant="h3" gutterBottom={true}>{t_i18n('Integration documentation and code')}</Typography>
              <Button
                variant="tertiary"
                startIcon={<LibraryBooksOutlined />}
                href={connector.source_code}
                target="blank"
                rel="noopener noreferrer"
              >
                {connector.title}
              </Button>
            </Grid>

            <Grid size={12}>
              <Typography variant="h3" gutterBottom={true}>{t_i18n('Visit the vendor\'s page to learn more and get in touch')}</Typography>
              <Button
                variant="tertiary"
                startIcon={<Launch />}
                href={connector.subscription_link}
                target="blank"
                rel="noopener noreferrer"
                disabled={!connector.subscription_link}
              >
                {t_i18n('Vendor contact')}
              </Button>
            </Grid>

            <Grid size={12}>
              <Typography variant="h3" gutterBottom={true}>{t_i18n('Last verified')}</Typography>
              {connector.last_verified_date || '-' }
            </Grid>
          </Grid>
        </Card>
      </Grid>
    </Grid>
  );
};

export default IngestionCatalogConnectorOverview;
