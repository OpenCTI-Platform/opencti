import { VerifiedOutlined } from '@mui/icons-material';
import React from 'react';
import { useTheme } from '@mui/styles';
import IngestionCatalogChip from '@private/components/data/IngestionCatalog/IngestionCatalogUseCaseChip';
import { IngestionConnector } from '@private/components/data/IngestionCatalog';
import EnterpriseEditionButton from '@private/components/common/entreprise_edition/EnterpriseEditionButton';
import { getConnectorMetadata } from '@private/components/data/IngestionCatalog/utils/ingestionConnectorTypeMetadata';
import { Button, Typography } from '@components';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { INGESTION_SETINGESTIONS } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import ItemBoolean from '../../../../components/ItemBoolean';

type IngestionCatalogConnectorHeaderProps = {
  connector: IngestionConnector,
  isEnterpriseEdition: boolean,
  onClickDeploy: () => void
};

const IngestionCatalogConnectorHeader = ({ connector, isEnterpriseEdition, onClickDeploy }: IngestionCatalogConnectorHeaderProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const connectorMetadata = getConnectorMetadata(connector.container_type, t_i18n);

  return (
    <>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: theme.spacing(2) }}>
        <div style={{ display: 'flex', gap: 20 }}>
          <img style={{ height: 70, width: 70, objectFit: 'cover', borderRadius: 4 }} src={connector.logo} alt={connector.title} />
          <div>
            <div style={{ display: 'flex', gap: 20 }}>
              <Typography variant="h1" style={{ fontSize: 30, textTransform: 'uppercase' }}>{connector.title}</Typography>
              {
                connector.verified && (
                  <ItemBoolean
                    status={true}
                    label={
                      <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
                        <VerifiedOutlined color="success" fontSize="small" />
                        {t_i18n('Verified')}
                      </div>
                    }
                  />
                )
              }
            </div>
            <div style={{ display: 'flex' }}>
              <IngestionCatalogChip
                isInlist
                label={connectorMetadata.label}
                color={connectorMetadata.color}
              />
              {connector.use_cases.map((useCase: string) => <IngestionCatalogChip key={useCase} label={useCase} isInlist />)}
            </div>
          </div>
        </div>

        <div>
          <Security needs={[INGESTION_SETINGESTIONS]}>
            {
              isEnterpriseEdition ? (
                <Button variant="contained" onClick={onClickDeploy} style={{ marginLeft: theme.spacing(1) }}>{t_i18n('Deploy')}</Button>
              ) : (
                <EnterpriseEditionButton title="Deploy" />
              )
            }
          </Security>
        </div>

      </div>
    </>
  );
};

export default IngestionCatalogConnectorHeader;
