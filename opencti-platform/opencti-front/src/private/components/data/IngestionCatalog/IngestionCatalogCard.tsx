import Card from '@mui/material/Card';
import React, { useState } from 'react';
import CardHeader from '@mui/material/CardHeader';
import CardContent from '@mui/material/CardContent';
import { Badge, CardActions, Grid } from '@mui/material';
import Button from '@mui/material/Button';
import { VerifiedOutlined } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import IngestionCatalogChip from '@components/data/IngestionCatalog/IngestionCatalogUseCaseChip';
import { useTheme } from '@mui/styles';
import IngestionCatalogConnectorCreation from '@components/data/IngestionCatalog/IngestionCatalogConnectorCreation';
import { IngestionConnector } from '@components/data/IngestionCatalog';
import { useFormatter } from '../../../../components/i18n';
import EnrichedTooltip from '../../../../components/EnrichedTooltip';
import { INGESTION_SETINGESTIONS } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import type { Theme } from '../../../../components/Theme';

interface IngestionCatalogCardProps {
  node: IngestionConnector;
  dataListId: string;
}

export type IngestionConnectorType = 'INTERNAL_ENRICHMENT' | 'EXTERNAL_IMPORT' | 'INTERNAL_EXPORT_FILE' | 'INTERNAL_IMPORT_FILE';

export const ingestionConnectorTypeMetadata: Record<IngestionConnectorType, { label: string; color: 'primary' | 'secondary' | 'error' | 'success' }> = {
  EXTERNAL_IMPORT: {
    label: 'External import',
    color: 'primary',
  },
  INTERNAL_ENRICHMENT: {
    label: 'Internal enrichment',
    color: 'secondary',
  },
  INTERNAL_EXPORT_FILE: {
    label: 'Internal export file',
    color: 'error',
  },
  INTERNAL_IMPORT_FILE: {
    label: 'Internal import file',
    color: 'success',
  },
};

const IngestionCatalogCard = ({ node: connector, dataListId }: IngestionCatalogCardProps) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const theme = useTheme<Theme>();
  const [openCreation, setOpenCreation] = useState(false);
  const link = `/dashboard/data/ingestion/catalog/${connector.slug}`;

  const renderLabels = () => {
    return (
      <EnrichedTooltip
        title={(
          <Grid container={true} spacing={3}>
            <Grid key={connector.container_type} item xs={6}>
              <IngestionCatalogChip
                withTooltip
                isInTooltip
                label={t_i18n(ingestionConnectorTypeMetadata[connector.container_type].label)}
                color={ingestionConnectorTypeMetadata[connector.container_type].color}
              />
            </Grid>
            {connector.use_cases.map((useCase: string) => <Grid key={useCase} item xs={6}><IngestionCatalogChip withTooltip isInTooltip label={useCase} /></Grid>)}
          </Grid>
        )}
      >
        {connector.use_cases.length > 0 ? (
          <Badge
            variant="dot"
            color="primary"
          >
            <IngestionCatalogChip
              label={t_i18n(ingestionConnectorTypeMetadata[connector.container_type].label)}
              color={ingestionConnectorTypeMetadata[connector.container_type].color}
            />
          </Badge>
        ) : (
          <IngestionCatalogChip
            label={t_i18n(ingestionConnectorTypeMetadata[connector.container_type].label)}
            color={ingestionConnectorTypeMetadata[connector.container_type].color}
          />
        )}
      </EnrichedTooltip>
    );
  };

  return (
    <>
      <Card
        variant="outlined"
        style={{
          height: 330,
          borderRadius: 4,
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
        }}
      >

        <CardHeader
          sx={{
            paddingBottom: 0,
            marginBottom: 0,
            alignItems: 'start',
            '& .MuiCardHeader-content': {
              minWidth: 0,
            },
          }}
          avatar={<img style={{ height: 50, width: 50, objectFit: 'cover', borderRadius: 4 }} src={connector.logo} alt={connector.title} />}
          title={<div style={{ width: '100%', fontSize: 20, fontWeight: 600, marginBottom: theme.spacing(1) }}>{connector.title}</div>}
          subheader={renderLabels()}
          action={connector.verified && <VerifiedOutlined color="success" />}
        />

        <CardContent style={{ height: '100%' }}>
          <div>{connector.short_description}</div>
        </CardContent>

        <CardActions style={{ alignSelf: 'end' }}>
          <Button variant="outlined" size="small" onClick={() => navigate(link)}>{t_i18n('Details')}</Button>
          <Security needs={[INGESTION_SETINGESTIONS]}>
            <Button variant="contained" onClick={() => setOpenCreation(true)} size="small">{t_i18n('Deploy')}</Button>
          </Security>
        </CardActions>

      </Card>

      <IngestionCatalogConnectorCreation open={openCreation} connector={connector} onClose={() => setOpenCreation(false)} catalogId={dataListId} />
    </>
  );
};

export default IngestionCatalogCard;
