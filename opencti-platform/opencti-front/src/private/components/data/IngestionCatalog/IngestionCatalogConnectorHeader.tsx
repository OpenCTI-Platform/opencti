import Typography from '@mui/material/Typography';
import { VerifiedOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import React from 'react';
import { useTheme } from '@mui/styles';
import IngestionCatalogChip from '@components/data/IngestionCatalog/IngestionCatalogUseCaseChip';
import { IngestionConnector } from '@components/data/IngestionCatalog';
import EnterpriseEditionButton from '@components/common/entreprise_edition/EnterpriseEditionButton';
import { getConnectorMetadata } from '@components/data/IngestionCatalog/utils/ingestionConnectorTypeMetadata';
import { Stack } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { INGESTION_SETINGESTIONS } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import ItemBoolean from '../../../../components/ItemBoolean';

type IngestionCatalogConnectorHeaderProps = {
  connector: IngestionConnector;
  isEnterpriseEdition: boolean;
  onClickDeploy: () => void;
};

const IngestionCatalogConnectorHeader = ({ connector, isEnterpriseEdition, onClickDeploy }: IngestionCatalogConnectorHeaderProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const connectorMetadata = getConnectorMetadata(connector.container_type, t_i18n);

  return (
    <Stack
      direction="row"
      justifyContent="space-between"
    >
      <Stack direction="row" gap={2}>
        <img
          src={connector.logo}
          alt={connector.title}
          style={{
            height: 96,
            width: 96,
            objectFit: 'cover',
            borderRadius: 4,
          }}
        />

        <Stack gap={1}>
          <Stack direction="row" gap={2} alignItems="center">
            <Typography
              variant="h1"
              sx={{
                fontWeight: 800,
                fontSize: 30,
                opacity: 0.9,
                marginBottom: 0,
                textTransform: 'uppercase',
              }}
            >
              {connector.title}
            </Typography>
            {
              connector.verified && (
                <ItemBoolean
                  status
                  label={(
                    <Stack direction="row" alignItems="center" gap={theme.spacing(1)}>
                      <VerifiedOutlined color="success" fontSize="small" />
                      {t_i18n('Verified')}
                    </Stack>
                  )}
                />
              )
            }
          </Stack>

          <Stack direction="row">
            <IngestionCatalogChip
              isInlist
              label={connectorMetadata.label}
              color={connectorMetadata.color}
            />

            {
              connector.use_cases.map((useCase: string) => (
                <IngestionCatalogChip key={useCase} label={useCase} isInlist color="primary" />
              ))
            }
          </Stack>
        </Stack>
      </Stack>

      <div>
        <Security needs={[INGESTION_SETINGESTIONS]}>
          {
            isEnterpriseEdition ? (
              <Button onClick={onClickDeploy} style={{ marginLeft: theme.spacing(1) }}>{t_i18n('Deploy')}</Button>
            ) : (
              <EnterpriseEditionButton title="Deploy" />
            )
          }
        </Security>
      </div>
    </Stack>
  );
};

export default IngestionCatalogConnectorHeader;
