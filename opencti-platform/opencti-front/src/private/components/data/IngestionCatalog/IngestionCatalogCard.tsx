import Card from '@mui/material/Card';
import React, { useState } from 'react';
import CardHeader from '@mui/material/CardHeader';
import CardContent from '@mui/material/CardContent';
import { Badge, CardActions, Grid, Tooltip } from '@mui/material';
import Button from '@mui/material/Button';
import { VerifiedOutlined } from '@mui/icons-material';
import { Link } from 'react-router-dom';
import IngestionCatalogChip from '@components/data/IngestionCatalog/IngestionCatalogUseCaseChip';
import { useTheme } from '@mui/styles';
import IngestionCatalogConnectorCreation from '@components/data/IngestionCatalog/IngestionCatalogConnectorCreation';
import { IngestionConnector } from '@components/data/IngestionCatalog';
import EnterpriseEditionButton from '@components/common/entreprise_edition/EnterpriseEditionButton';
import { truncate } from 'src/utils/String';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import { useFormatter } from '../../../../components/i18n';
import EnrichedTooltip from '../../../../components/EnrichedTooltip';
import { INGESTION_SETINGESTIONS } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import type { Theme } from '../../../../components/Theme';

export interface IngestionCatalogCardProps {
  node: IngestionConnector;
  dataListId: string;
  isEnterpriseEdition: boolean
  deploymentCount?: number;
}

export type IngestionConnectorType =
  | 'INTERNAL_ENRICHMENT'
  | 'EXTERNAL_IMPORT'
  | 'INTERNAL_EXPORT_FILE'
  | 'INTERNAL_IMPORT_FILE';

export const ingestionConnectorTypeMetadata: Record<
IngestionConnectorType,
{ label: string; color: 'primary' | 'secondary' | 'error' | 'success' }
> = {
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

type RenderConnectorUseCasesType = {
  useCases: string[];
  withTooltip?: boolean;
  withBadge?: boolean;
};

const DeployButton = ({ deploymentCount, onClick }: { deploymentCount?: number, onClick: () => void }) => {
  const { t_i18n } = useFormatter();

  return (
    <Tooltip title={deploymentCount ? `${deploymentCount} deployments` : '' }>
      <Badge badgeContent={deploymentCount} color={'warning'}>
        <Button
          variant="contained"
          onClick={onClick}
          size="small"
        >
          {t_i18n('Deploy')}
        </Button>
      </Badge>
    </Tooltip>
  );
};

const IngestionCatalogCard = ({
  node: connector,
  dataListId,
  isEnterpriseEdition,
  deploymentCount = 0,
}: IngestionCatalogCardProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [openCreation, setOpenCreation] = useState(false);
  const link = `/dashboard/data/ingestion/catalog/${connector.slug}`;

  const renderConnectorUseCases = ({
    useCases,
    withTooltip = true,
    withBadge = false,
  }: RenderConnectorUseCasesType) => {
    const renderUseCaseWithBadge = (useCase: string) => (
      <Badge variant="dot" color="primary" sx={{ width: '100%' }}>
        <IngestionCatalogChip
          withTooltip={withTooltip}
          isInTooltip
          label={useCase}
        />
      </Badge>
    );

    return (
      <Grid container spacing={1}>
        {useCases.map((useCase: string, index: number) => (
          <Grid key={useCase} item xs={6}>
            {withBadge && index === 1 ? (
              renderUseCaseWithBadge(useCase)
            ) : (
              <IngestionCatalogChip
                withTooltip={withTooltip}
                isInTooltip
                label={useCase}
              />
            )}
          </Grid>
        ))}
      </Grid>
    );
  };

  const renderLabels = () => {
    const hasMoreThanTwoUseCases = connector.use_cases.length > 2;
    if (hasMoreThanTwoUseCases) {
      const slicedList = connector.use_cases.slice(0, 2);
      return (
        <EnrichedTooltip
          title={renderConnectorUseCases({ useCases: connector.use_cases })}
        >
          {renderConnectorUseCases({
            useCases: slicedList,
            withTooltip: false,
            withBadge: true,
          })}
        </EnrichedTooltip>
      );
    }

    return renderConnectorUseCases({
      useCases: connector.use_cases,
      withBadge: hasMoreThanTwoUseCases,
    });
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
        <div>
          <CardHeader
            sx={{
              paddingBottom: 0,
              marginBottom: 0,
              alignItems: 'start',
              '& .MuiCardHeader-content': {
                minWidth: 0,
              },
            }}
            avatar={
              <img
                style={{
                  height: 50,
                  width: 50,
                  objectFit: 'contain',
                  borderRadius: 4,
                }}
                src={connector.logo}
                alt={connector.title}
              />
            }
            title={
              <Tooltip title={connector.title} placement="top">
                <div
                  style={{
                    width: '100%',
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    fontSize: 20,
                    fontWeight: 600,
                    marginBottom: theme.spacing(1),
                  }}
                >
                  {connector.title}
                </div>
              </Tooltip>
            }
            subheader={renderLabels()}
            action={connector.verified && <VerifiedOutlined color="success" />}
          />

          <CardContent
            style={{
              height: '100%',
              marginBottom: 32,
            }}
          >
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Description')}
            </Typography>
            <div>{truncate(connector.short_description, 100)}</div>
          </CardContent>
        </div>
        <CardActions style={{ justifyContent: 'space-between', padding: 16 }}>
          <IngestionCatalogChip
            label={t_i18n(
              ingestionConnectorTypeMetadata[connector.container_type].label,
            )}
            color={
                ingestionConnectorTypeMetadata[connector.container_type].color
              }
          />
          <div style={{ display: 'flex', gap: 4 }}>
            <Button variant="outlined" size="small" component={Link} to={link}>
              {t_i18n('Details')}
            </Button>
            <Security needs={[INGESTION_SETINGESTIONS]}>
              {
                isEnterpriseEdition ? (
                  <DeployButton deploymentCount={deploymentCount} onClick={() => setOpenCreation(true)} />
                ) : (
                  <Box sx={{ '& .MuiButton-root': { marginLeft: 0 } }}>
                    {/** FIXME: remove marginLeft in EnterpriseEditionButton * */}
                    <EnterpriseEditionButton title="Deploy" />
                  </Box>
                )
              }
            </Security>
          </div>
        </CardActions>
      </Card>

      <IngestionCatalogConnectorCreation
        open={openCreation}
        connector={connector}
        onClose={() => setOpenCreation(false)}
        catalogId={dataListId}
      />
    </>
  );
};

export default IngestionCatalogCard;
