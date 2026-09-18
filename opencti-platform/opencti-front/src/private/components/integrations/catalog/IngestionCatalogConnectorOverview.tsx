import Button from '@common/button/Button';
import { Launch } from 'mdi-material-ui';
import Alert from '@mui/material/Alert';
import Grid from '@mui/material/Grid2';
import { IngestionConnector } from '@components/integrations/catalog/types';
import { LibraryBooksOutlined } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import MarkdownDisplay from '../../../../components/markdownDisplay/MarkdownDisplay';
import Card from '../../../../components/common/card/Card';
import Label from '../../../../components/common/label/Label';
import { EMPTY_VALUE } from '../../../../utils/String';

const IngestionCatalogConnectorOverview = ({ connector }: { connector: IngestionConnector }) => {
  const { t_i18n } = useFormatter();
  const latestCompatibleVersion = connector.compatibility?.latest_compatible_version ?? null;
  const minimumPlatformVersion = connector.compatibility?.minimum_platform_version ?? null;
  const shouldShowCompatibilityAlert = connector.manager_supported && connector.compatibility?.is_compatible === false && !!minimumPlatformVersion;

  return (
    <Grid container spacing={2} sx={{ marginBottom: 20 }}>
      <Grid size={{ xs: 12, md: 8 }}>
        <Card title={t_i18n('Overview')}>
          {shouldShowCompatibilityAlert && (
            <Alert severity="info" sx={{ marginBottom: 2 }}>
              {t_i18n(`This connector is not compatible with your current platform version. Please upgrade your platform to ${minimumPlatformVersion} or above.`)}
            </Alert>
          )}
          <MarkdownDisplay content={connector.description} />
        </Card>
      </Grid>

      <Grid size={{ xs: 12, md: 4 }}>
        <Card title={t_i18n('Basic information')}>
          <Grid container spacing={2.5}>
            <Grid size={12}>
              <Label>
                {t_i18n('Integration documentation and code')}
              </Label>
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
              <Label>
                {t_i18n('Visit the vendor\'s page to learn more and get in touch')}
              </Label>
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
              <Label>
                {t_i18n('Latest Compatible Version')}
              </Label>
              {latestCompatibleVersion ?? t_i18n('None')}
            </Grid>

            <Grid size={12}>
              <Label>
                {t_i18n('Last verified')}
              </Label>
              {connector.last_verified_date || EMPTY_VALUE}
            </Grid>
          </Grid>
        </Card>
      </Grid>
    </Grid>
  );
};

export default IngestionCatalogConnectorOverview;
