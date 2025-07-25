import Typography from '@mui/material/Typography';
import { VerifiedOutlined } from '@mui/icons-material';
import Button from '@mui/material/Button';
import { Launch } from 'mdi-material-ui';
import React, { useState } from 'react';
import { useTheme } from '@mui/styles';
import { IngestionConnector, ingestionConnectorTypeMetadata } from '@components/data/IngestionCatalog/IngestionCatalogCard';
import IngestionCatalogChip from '@components/data/IngestionCatalog/IngestionCatalogUseCaseChip';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { INGESTION_SETINGESTIONS } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import ItemBoolean from '../../../../components/ItemBoolean';
import IngestionCatalogConnectorCreation from '@components/data/IngestionCatalog/IngestionCatalogConnectorCreation';

const IngestionCatalogConnectorHeader = ({ connector, contract }: { connector: IngestionConnector, contract: string }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [openCreation, setOpenCreation] = useState(false);

  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: theme.spacing(2) }}>

      <div style={{ display: 'flex', gap: 20 }}>
        <img style={{ height: 70, width: 70, objectFit: 'cover', borderRadius: 4 }} src={connector.logo} alt={connector.title} />
        <div>
          <div style={{ display: 'flex', gap: 20 }}>
            <Typography variant="h1" style={{ fontSize: 30, textTransform: 'uppercase' }}>{connector.title}</Typography>
            {connector.verified && (
              <ItemBoolean
                status={true}
                label={
                  <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
                    <VerifiedOutlined color="success" fontSize="small" />
                    {t_i18n('Verified')}
                  </div>
                }
              />
            )}
          </div>
          <div style={{ display: 'flex' }}>
            <IngestionCatalogChip
              isInlist
              label={t_i18n(ingestionConnectorTypeMetadata[connector.container_type].label)}
              color={ingestionConnectorTypeMetadata[connector.container_type].color}
            />
            {connector.use_cases.map((useCase: string) => <IngestionCatalogChip key={useCase} label={useCase} isInlist />)}
          </div>
        </div>
      </div>

      <div>
        <Button
          variant="outlined"
          startIcon={<Launch />}
          href={connector.subscription_link}
          target="blank"
          rel="noopener noreferrer"
        >
          {t_i18n('', { id: 'Test ... with OpenCTI', values: { connectorName: connector.title } })}
        </Button>
        <Security needs={[INGESTION_SETINGESTIONS]}>
          <Button variant="contained" onClick={() => setOpenCreation(true)} style={{ marginLeft: theme.spacing(1) }}>{t_i18n('Deploy')}</Button>
        </Security>
      </div>

      <IngestionCatalogConnectorCreation open={openCreation} connector={connector} contract={contract} onClose={() => setOpenCreation(false)} />

    </div>
  );
};

export default IngestionCatalogConnectorHeader;
