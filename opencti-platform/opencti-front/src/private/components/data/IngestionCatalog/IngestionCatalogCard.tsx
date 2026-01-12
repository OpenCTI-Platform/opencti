import CardHeader from '@mui/material/CardHeader';
import CardContent from '@mui/material/CardContent';
import { CardActions, Stack, Typography } from '@mui/material';
import { VerifiedOutlined } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { useTheme } from '@mui/styles';
import { IngestionConnector } from '@components/data/IngestionCatalog';
import EnterpriseEditionButton from '@components/common/entreprise_edition/EnterpriseEditionButton';
import { getConnectorMetadata } from '@components/data/IngestionCatalog/utils/ingestionConnectorTypeMetadata';
import Box from '@mui/material/Box';
import IngestionCatalogCardDeployButton from '@components/data/IngestionCatalog/components/card/IngestionCatalogCardDeployButton';
import ConnectorUseCases from '@components/data/IngestionCatalog/components/card/usecases/ConnectorUseCases';
import Tooltip from '@mui/material/Tooltip';
import { useFormatter } from '../../../../components/i18n';
import { INGESTION_SETINGESTIONS } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import type { Theme } from '../../../../components/Theme';
import Card from '../../../../components/common/card/Card';

export interface IngestionCatalogCardProps {
  node: IngestionConnector;
  dataListId: string;
  isEnterpriseEdition: boolean;
  onClickDeploy: () => void;
  deploymentCount?: number;
}

interface ConnectorLogoProps {
  src: string;
  alt: string;
}

const ConnectorLogo = ({ src, alt }: ConnectorLogoProps) => {
  return (
    <img
      style={{
        height: 80,
        width: 80,
        borderRadius: 4,
      }}
      src={src}
      alt={alt}
    />
  );
};

interface ConnectorTitleProps {
  title: string;
}

const ConnectorTitle = ({ title }: ConnectorTitleProps) => {
  return (
    <Tooltip title={title} placement="bottom-start">
      <Typography
        variant="h1"
        sx={{
          fontWeight: 800,
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          display: '-webkit-box',
          WebkitLineClamp: 2,
          WebkitBoxOrient: 'vertical',
          opacity: 0.9,
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
              onClick={onClickDeploy}
            />
          ) : (
            <Box sx={{ '& .MuiButton-root': { marginLeft: 0 } }}>
              {/** FIXME: remove marginLeft in EnterpriseEditionButton * */}
              <EnterpriseEditionButton title="Deploy" />
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
  const theme = useTheme<Theme>();

  const navigate = useNavigate();

  const link = `/dashboard/data/ingestion/catalog/${connector.slug}`;

  const connectorMetadata = getConnectorMetadata(
    connector.container_type,
    t_i18n,
  );

  const handleCardClick = () => {
    navigate(link);
  };

  return (
    <Card
      onClick={handleCardClick}
      sx={{
        height: 330,
        borderRadius: 1,
        display: 'flex',
        flexDirection: 'column',
        cursor: 'pointer',
        transition: 'background-color 0.2s ease-in-out',
        '&:hover': {
          backgroundColor: theme.palette.action?.hover,
        },
      }}
    >
      <CardHeader
        sx={{
          width: '100%',
          padding: 0,
          paddingBottom: 3,
          alignItems: 'flex-start',
          '& .MuiCardHeader-content': {
            minWidth: 0,
            overflow: 'hidden',
            width: '100%',
          },
          '& .MuiCardHeader-action': {
            marginTop: 0,
          },
        }}
        avatar={<ConnectorLogo src={connector.logo} alt={connector.title} />}
        title={(
          <>
            <Typography
              variant="body2"
              color={theme.palette.primary.main}
              gutterBottom
            >
              {connectorMetadata.label}
            </Typography>
            <ConnectorTitle title={connector.title} />
          </>
        )}
        action={connector.verified && <VerifiedOutlined color="success" />}
      />

      <CardContent
        sx={{
          flexGrow: 1,
          padding: 0,
          overflow: 'hidden',
          display: 'flex',
          alignItems: 'flex-start',
        }}
      >
        <Typography
          variant="body2"
          sx={{
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            display: '-webkit-box',
            WebkitLineClamp: 5,
            WebkitBoxOrient: 'vertical',
            lineHeight: 1.5,
            opacity: 0.8,
          }}
        >
          {connector.short_description}
        </Typography>
      </CardContent>

      <ConnectorActions
        connector={connector}
        isEnterpriseEdition={isEnterpriseEdition}
        deploymentCount={deploymentCount}
        onClickDeploy={onClickDeploy}
      />
    </Card>
  );
};

export default IngestionCatalogCard;
