import React from 'react';
import { CardActions, Stack, Typography } from '@mui/material';
import { GroupsOutlined } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { alpha, useTheme } from '@mui/material/styles';
import { IngestionConnector } from '@components/integrations/catalog/types';
import EnterpriseEditionButton from '@components/common/entreprise_edition/EnterpriseEditionButton';
import { getConnectorMetadata } from '@components/integrations/catalog/utils/ingestionConnectorTypeMetadata';
import Box from '@mui/material/Box';
import IngestionCatalogCardDeployButton from '@components/integrations/catalog/components/card/IngestionCatalogCardDeployButton';
import ConnectorUseCases from '@components/integrations/catalog/components/card/usecases/ConnectorUseCases';
import Tooltip from '@mui/material/Tooltip';
import { useFormatter } from '../../../../components/i18n';
import { INGESTION_SETINGESTIONS } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import Card from '../../../../components/common/card/Card';
import FiligranIcon from '@components/common/FiligranIcon';
import { LogoFiligranIcon } from 'filigran-icon';

export interface IngestionCatalogCardProps {
  node: IngestionConnector;
  isEnterpriseEdition: boolean;
  onClickDeploy: () => void;
  deploymentCount?: number;
}

interface ConnectorLogoProps {
  src: string;
  alt: string;
}

const ConnectorLogo = ({ src, alt }: ConnectorLogoProps) => {
  const theme = useTheme();
  return (
    <Box
      sx={{
        height: 56,
        width: 56,
        flexShrink: 0,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        borderRadius: 1,
        border: `1px solid ${alpha(theme.palette.text.primary, 0.1)}`,
        backgroundColor: alpha(theme.palette.text.primary, 0.04),
      }}
    >
      <img
        style={{
          height: 44,
          width: 44,
          objectFit: 'contain',
          borderRadius: 4,
        }}
        src={src}
        alt={alt}
      />
    </Box>
  );
};

interface ConnectorTitleProps {
  title: string;
}

const ConnectorTitle = ({ title }: ConnectorTitleProps) => {
  return (
    <Tooltip title={title} placement="bottom-start">
      <Typography
        sx={{
          fontSize: 15,
          fontWeight: 600,
          lineHeight: 1.35,
          display: '-webkit-box',
          WebkitLineClamp: 2,
          WebkitBoxOrient: 'vertical',
          overflow: 'hidden',
          wordBreak: 'break-word',
        }}
      >
        {title}
      </Typography>
    </Tooltip>
  );
};

interface ConnectorActionsProps {
  connector: IngestionConnector;
  isEnterpriseEdition: boolean;
  deploymentCount: number;
  onClickDeploy: () => void;
}

const ConnectorActions = ({
  connector,
  isEnterpriseEdition,
  deploymentCount,
  onClickDeploy,
}: ConnectorActionsProps) => {
  return (
    <CardActions
      sx={{
        width: '100%',
        justifyContent: 'space-between',
        padding: 0,
        flexWrap: 'nowrap',
        gap: 1,
        alignItems: 'flex-end',
      }}
    >
      <ConnectorUseCases useCases={connector.use_cases} />
      <Stack
        sx={{ marginLeft: '0!important' }}
        direction="row"
        gap={1}
        onClick={(e) => e.stopPropagation()}
      >
        <Security needs={[INGESTION_SETINGESTIONS]}>
          {isEnterpriseEdition ? (
            <IngestionCatalogCardDeployButton
              deploymentCount={deploymentCount}
              deployedTo={`/dashboard/integrations/deployed?search=${encodeURIComponent(connector.title)}`}
              onClick={onClickDeploy}
            />
          ) : (
            <Box sx={{ '& .MuiButton-root': { marginLeft: 0 } }}>
              {/** FIXME: remove marginLeft in EnterpriseEditionButton * */}
              <EnterpriseEditionButton title="Deploy" feature="Connector deployment" withEEChip />
            </Box>
          )}
        </Security>
      </Stack>
    </CardActions>
  );
};

const IngestionCatalogCard = ({
  node: connector,
  isEnterpriseEdition,
  onClickDeploy,
  deploymentCount = 0,
}: IngestionCatalogCardProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();

  const navigate = useNavigate();

  const link = `/dashboard/integrations/catalog/${connector.slug}`;

  const connectorMetadata = getConnectorMetadata(
    connector.container_type,
    t_i18n,
  );

  const handleCardClick = () => {
    navigate(link);
  };

  return (
    <Box
      data-testid="connector-card"
      sx={{
        height: '100%',
        '& .MuiCard-root': {
          border: `1px solid ${alpha(theme.palette.text.primary, 0.08)}`,
          transition: 'transform 0.3s ease-in-out, border-color 0.3s ease-in-out, box-shadow 0.3s ease-in-out',
        },
        '&:hover .MuiCard-root': {
          transform: 'translateY(-2px)',
          borderColor: alpha(theme.palette.primary.main, 0.3),
          boxShadow: `0 0 30px ${alpha(theme.palette.primary.main, 0.12)}`,
        },
      }}
    >
      <Card
        onClick={handleCardClick}
        sx={{
          height: 280,
          borderRadius: 1,
          display: 'flex',
          flexDirection: 'column',
          gap: 2,
          cursor: 'pointer',
          alignItems: 'stretch',
        }}
      >
        <Stack direction="row" gap={1.5} alignItems="flex-start" sx={{ width: '100%' }}>
          <ConnectorLogo src={connector.logo} alt={connector.title} />
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Typography
              variant="body2"
              sx={{
                color: theme.palette.primary.main,
                fontSize: 12,
                fontWeight: 500,
                letterSpacing: '0.06em',
                textTransform: 'uppercase',
                marginBottom: 0.5,
              }}
            >
              {connectorMetadata.label}
            </Typography>
            <ConnectorTitle title={connector.title} />
          </Box>
          <Tooltip
            title={
              connector.verified
                ? t_i18n('Supported by Filigran')
                : t_i18n('Supported by Community')
            }
            slotProps={{ popper: { sx: { textTransform: 'none' } } }}
          >
            {connector.verified ? (
              <span style={{ display: 'inline-flex' }}>
                <FiligranIcon
                  icon={LogoFiligranIcon}
                  size="small"
                  style={{ color: theme.palette.primary.main }}
                />
              </span>
            ) : (
              <GroupsOutlined color="disabled" />
            )}
          </Tooltip>
        </Stack>

        <Box sx={{ flexGrow: 1, overflow: 'hidden', width: '100%' }}>
          <Typography
            variant="body2"
            sx={{
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              display: '-webkit-box',
              WebkitLineClamp: 4,
              WebkitBoxOrient: 'vertical',
              lineHeight: 1.5,
              color: theme.palette.text.secondary,
            }}
          >
            {connector.short_description}
          </Typography>
        </Box>

        <ConnectorActions
          connector={connector}
          isEnterpriseEdition={isEnterpriseEdition}
          deploymentCount={deploymentCount}
          onClickDeploy={onClickDeploy}
        />
      </Card>
    </Box>
  );
};

export default IngestionCatalogCard;
