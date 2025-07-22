import Typography from '@mui/material/Typography';
import Chip from '@mui/material/Chip';
import { VerifiedOutlined } from '@mui/icons-material';
import IngestionCatalogUseCaseChip from '@components/data/IngestionCatalog/IngestionCatalogUseCaseChip';
import Button from '@mui/material/Button';
import { Launch } from 'mdi-material-ui';
import React from 'react';
import { useTheme } from '@mui/styles';
import { IngestionCatalogConnectorConnectorProps } from '@components/data/IngestionCatalog/IngestionCatalogConnector';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';

const IngestionCatalogConnectorHeader = ({ connector }: IngestionCatalogConnectorConnectorProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: theme.spacing(2) }}>

      <div style={{ display: 'flex', gap: 20 }}>
        <img style={{ height: 37, maxWidth: 100, borderRadius: 4 }} src={connector.logo} alt={connector.title} />
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
            <Typography variant="h1" style={{ textTransform: 'uppercase', marginBottom: 0 }}>{connector.title}</Typography>
            <Chip
              style={{ textTransform: 'uppercase', borderRadius: 4 }}
              icon={<VerifiedOutlined color="success" />}
              label={<Typography color="success">{t_i18n('Verified')}</Typography>}
            />
          </div>
          <div style={{ display: 'flex' }}>
            {connector.use_cases.map((useCase: string) => <IngestionCatalogUseCaseChip key={useCase} useCase={useCase} />)}
          </div>
        </div>
      </div>

      <div>
        <Button variant="contained" disabled>{t_i18n('Deploy')}</Button>
        <Button
          variant="contained"
          startIcon={<Launch />}
          style={{ marginLeft: theme.spacing(2) }}
          href={connector.subscription_link}
          target="blank"
          rel="noopener noreferrer"
        >
          {t_i18n('', { id: 'Test ... with OpenCTI', values: { connectorName: connector.default.CONNECTOR_NAME } })}
        </Button>
      </div>

    </div>
  );
};

export default IngestionCatalogConnectorHeader;
