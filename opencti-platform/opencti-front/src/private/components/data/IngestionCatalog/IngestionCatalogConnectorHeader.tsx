import Typography from '@mui/material/Typography';
import { VerifiedOutlined } from '@mui/icons-material';
import Button from '@mui/material/Button';
import React, { useState } from 'react';
import { useTheme } from '@mui/styles';
import { ingestionConnectorTypeMetadata } from '@components/data/IngestionCatalog/IngestionCatalogCard';
import IngestionCatalogChip from '@components/data/IngestionCatalog/IngestionCatalogUseCaseChip';
import IngestionCatalogConnectorCreation from '@components/data/IngestionCatalog/IngestionCatalogConnectorCreation';
import { IngestionConnector } from '@components/data/IngestionCatalog';
import EnterpriseEditionButton from '@components/common/entreprise_edition/EnterpriseEditionButton';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { INGESTION_SETINGESTIONS } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import ItemBoolean from '../../../../components/ItemBoolean';

type IngestionCatalogConnectorHeaderProps = {
  connector: IngestionConnector,
  catalogId: string,
  isEnterpriseEdition: boolean,
};

const IngestionCatalogConnectorHeader = ({ connector, catalogId, isEnterpriseEdition }: IngestionCatalogConnectorHeaderProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [openCreation, setOpenCreation] = useState(false);

  return (
    <>
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
          <Security needs={[INGESTION_SETINGESTIONS]}>
            {
              isEnterpriseEdition ? (
                <Button variant="contained" onClick={() => setOpenCreation(true)} style={{ marginLeft: theme.spacing(1) }}>{t_i18n('Deploy')}</Button>
              ) : (
                <EnterpriseEditionButton title="Deploy" />
              )
            }
          </Security>
        </div>

        <IngestionCatalogConnectorCreation open={openCreation} connector={connector} onClose={() => setOpenCreation(false)} catalogId={catalogId} />

      </div>
    </>
  );
};

export default IngestionCatalogConnectorHeader;
