import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Stack, Tooltip, Typography } from '@mui/material';
import Box from '@mui/material/Box';
import { alpha, useTheme } from '@mui/material/styles';
import { GroupsOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import EnterpriseEditionButton from '@components/common/entreprise_edition/EnterpriseEditionButton';
import FiligranIcon from '@components/common/FiligranIcon';
import { CatalogItem } from '@components/integrations/catalog/hooks/useIngestionCatalogFilters';
import { getConnectorMetadata } from '@components/integrations/catalog/utils/ingestionConnectorTypeMetadata';
import { BuiltInIntegrationHubButton, BuiltInIntegrationImport, isImportableBuiltInKind } from '@components/integrations/available/BuiltInIntegrationImport';
import { DeployedCountChip } from '@components/integrations/components/MarketplaceUi';
import { LogoFiligranIcon } from 'filigran-icon';
import { useFormatter } from '../../../../components/i18n';
import useGranted, { INGESTION_SETINGESTIONS } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import { EMPTY_VALUE } from '../../../../utils/String';
import { paperBorder } from '../paperSurface';

// Shared column geometry between the header row and the lines, mirroring the
// deployed tab lines view: the name column absorbs the remaining space and
// secondary columns collapse on small screens instead of squeezing the names.
const COLUMNS = {
  type: { width: '13%', minWidth: 110, display: { xs: 'none', sm: 'flex' } },
  description: { width: '24%', display: { xs: 'none', lg: 'flex' } },
  status: { width: '10%', minWidth: 96, display: { xs: 'none', md: 'flex' } },
  deployed: { width: '11%', minWidth: 110, display: { xs: 'none', sm: 'flex' } },
  actions: { width: '16%', minWidth: 150, display: 'flex', justifyContent: 'flex-end' },
} as const;

const cellSx = (column: keyof typeof COLUMNS) => ({
  ...COLUMNS[column],
  flexShrink: 0,
  alignItems: 'center',
});

// Column headers rendered once at the top of each section container.
export const AvailableIntegrationLinesHeader = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const headerCellSx = {
    fontSize: 10,
    fontWeight: 600,
    textTransform: 'uppercase',
    letterSpacing: 0.5,
    color: theme.palette.text.secondary,
    lineHeight: 1,
  };
  return (
    <Box
      sx={{
        display: 'flex',
        alignItems: 'center',
        gap: 1.5,
        paddingInline: 1.5,
        paddingBlock: 1,
        backgroundColor: alpha(theme.palette.text.primary, 0.02),
        borderBottom: `1px solid ${paperBorder(theme)}`,
      }}
    >
      <Typography component="div" sx={{ ...headerCellSx, flex: 1, minWidth: 0 }}>
        {t_i18n('Name')}
      </Typography>
      <Typography component="div" sx={{ ...headerCellSx, ...cellSx('type') }}>
        {t_i18n('Type')}
      </Typography>
      <Typography component="div" sx={{ ...headerCellSx, ...cellSx('description') }}>
        {t_i18n('Description')}
      </Typography>
      <Typography component="div" sx={{ ...headerCellSx, ...cellSx('status') }}>
        {t_i18n('Support')}
      </Typography>
      <Typography component="div" sx={{ ...headerCellSx, ...cellSx('deployed') }}>
        {t_i18n('Deployments')}
      </Typography>
      <Box sx={cellSx('actions')} />
    </Box>
  );
};

export interface AvailableIntegrationLineProps {
  item: CatalogItem;
  isEnterpriseEdition: boolean;
  onClickDeploy: () => void;
  onClickCreate: () => void;
}

// Compact row variant of the available tab cards (marketplace connectors and
// built-in ingestion methods). Cells share their geometry with
// AvailableIntegrationLinesHeader so rows align like a table.
const AvailableIntegrationLine = ({ item, isEnterpriseEdition, onClickDeploy, onClickCreate }: AvailableIntegrationLineProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const navigate = useNavigate();
  const canCreate = useGranted([INGESTION_SETINGESTIONS]);

  const connector = item.connector?.connector;
  const BuiltInIcon = item.builtIn?.icon;

  const typeLabel = connector
    ? getConnectorMetadata(connector.container_type, t_i18n).label
    : t_i18n('Built-in');
  const description = connector
    ? connector.short_description
    : t_i18n(item.builtIn?.description ?? '');

  // Opening a connector line navigates to its catalog detail; a built-in line
  // opens its creation drawer (like the matching cards).
  const handleLineClick = () => {
    if (connector) {
      navigate(`/dashboard/integrations/catalog/${connector.slug}`);
    } else if (canCreate) {
      onClickCreate();
    }
  };

  return (
    <Box
      data-testid="available-integration-line"
      onClick={handleLineClick}
      sx={{
        display: 'flex',
        alignItems: 'center',
        gap: 1.5,
        paddingInline: 1.5,
        paddingBlock: 0.75,
        cursor: connector || canCreate ? 'pointer' : undefined,
        transition: 'background-color 0.2s ease-in-out',
        '&:hover': {
          backgroundColor: theme.palette.action.hover,
        },
        '& + &': {
          borderTop: `1px solid ${alpha(theme.palette.text.primary, 0.05)}`,
        },
      }}
    >
      {/* Name column: logo or built-in icon, then the name. */}
      <Stack direction="row" alignItems="center" gap={1.5} sx={{ flex: 1, minWidth: 0 }}>
        <Box
          sx={{
            height: 32,
            width: 32,
            flexShrink: 0,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            borderRadius: 1,
            border: `1px solid ${alpha(theme.palette.text.primary, 0.1)}`,
            backgroundColor: alpha(theme.palette.text.primary, 0.04),
          }}
        >
          {connector ? (
            <img
              style={{ height: 24, width: 24, objectFit: 'contain', borderRadius: 3 }}
              src={connector.logo}
              alt={item.title}
            />
          ) : (
            BuiltInIcon && <BuiltInIcon sx={{ fontSize: 18, color: theme.palette.primary.main }} />
          )}
        </Box>
        <Tooltip title={item.title} placement="bottom-start">
          <Typography
            sx={{
              fontSize: 13,
              // Allow the flex child to shrink so long names truncate with an
              // ellipsis instead of pushing the other columns.
              minWidth: 0,
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
            }}
          >
            {item.title}
          </Typography>
        </Tooltip>
      </Stack>
      {/* Type column. */}
      <Box sx={cellSx('type')}>
        <Typography
          sx={{
            fontSize: 12,
            color: theme.palette.primary.main,
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
          }}
        >
          {typeLabel}
        </Typography>
      </Box>
      {/* Description column. */}
      <Box sx={cellSx('description')}>
        <Typography
          sx={{
            fontSize: 12,
            color: theme.palette.text.secondary,
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
          }}
        >
          {description || EMPTY_VALUE}
        </Typography>
      </Box>
      {/* Support column: Filigran verified or community. */}
      <Box sx={cellSx('status')}>
        <Tooltip
          title={item.verified ? t_i18n('Supported by Filigran') : t_i18n('Supported by Community')}
          slotProps={{ popper: { sx: { textTransform: 'none' } } }}
        >
          <Stack direction="row" alignItems="center" gap={0.5}>
            {item.verified ? (
              <span style={{ display: 'inline-flex' }}>
                <FiligranIcon
                  icon={LogoFiligranIcon}
                  size="small"
                  style={{ color: theme.palette.primary.main }}
                />
              </span>
            ) : (
              <GroupsOutlined sx={{ fontSize: 16 }} color="disabled" />
            )}
            <Typography sx={{ fontSize: 12, color: theme.palette.text.secondary, whiteSpace: 'nowrap' }}>
              {item.verified ? t_i18n('Filigran') : t_i18n('Community')}
            </Typography>
          </Stack>
        </Tooltip>
      </Box>
      {/* Deployments column. */}
      <Box sx={cellSx('deployed')}>
        {item.deploymentCount > 0 ? (
          <DeployedCountChip
            count={item.deploymentCount}
            to={item.builtIn
              ? `/dashboard/integrations/deployed?type=${item.builtIn.kind}`
              : `/dashboard/integrations/deployed?search=${encodeURIComponent(item.title)}`}
          />
        ) : (
          <Typography sx={{ fontSize: 12, color: theme.palette.text.secondary }}>
            {EMPTY_VALUE}
          </Typography>
        )}
      </Box>
      {/* Actions column. */}
      <Box onClick={(event) => event.stopPropagation()} sx={cellSx('actions')}>
        <Security needs={[INGESTION_SETINGESTIONS]}>
          {item.builtIn ? (
            <Stack direction="row" alignItems="center">
              {isImportableBuiltInKind(item.builtIn.kind) && (
                <>
                  <BuiltInIntegrationImport kind={item.builtIn.kind} />
                  <BuiltInIntegrationHubButton kind={item.builtIn.kind} />
                </>
              )}
              <Button size="small" onClick={onClickCreate} sx={{ marginLeft: 1 }}>
                {t_i18n('Create')}
              </Button>
            </Stack>
          ) : (
            <>
              {isEnterpriseEdition ? (
                <Button size="small" onClick={onClickDeploy}>
                  {t_i18n('Deploy')}
                </Button>
              ) : (
                <Box sx={{ '& .MuiButton-root': { marginLeft: 0 } }}>
                  <EnterpriseEditionButton title="Deploy" feature="Connector deployment" withEEChip />
                </Box>
              )}
            </>
          )}
        </Security>
      </Box>
    </Box>
  );
};

export default AvailableIntegrationLine;
