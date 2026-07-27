import React, { useContext } from 'react';
import { Box, Chip, IconButton, Stack, Tooltip, Typography } from '@mui/material';
import { CheckCircleOutlined, ExpandMoreOutlined, Search } from '@mui/icons-material';
import type { SvgIconComponent } from '@mui/icons-material';
import { alpha, useTheme } from '@mui/material/styles';
import { useNavigate } from 'react-router-dom';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import GradientCard from '../../../../components/GradientCard';
import { UserContext } from '../../../../utils/hooks/useAuth';
import { isNotEmptyField } from '../../../../utils/utils';

export const BrowseMoreButton = () => {
  const { t_i18n } = useFormatter();
  const { settings } = useContext(UserContext);
  // Hidden when the platform is not linked to an XTM Hub (same behavior as the
  // Import from Hub buttons of the legacy feed screens).
  if (!isNotEmptyField(settings?.platform_xtmhub_url)) return null;
  const browseHubCatalog = `${settings.platform_xtmhub_url}/cybersecurity-solutions/open-cti-integrations`;
  return (
    <Button
      gradient
      variant="secondary"
      href={browseHubCatalog}
      target="_blank"
      rel="noopener noreferrer"
      title={t_i18n('Browse More')}
    >
      {t_i18n('Browse More')}
    </Button>
  );
};

// Deployed-instances indicator on catalog cards: a discreet success chip with
// a tooltip (same design as the OpenAEV integrations catalog). When a target
// is provided, clicking the chip opens the deployed tab with matching filters.
export const DeployedCountChip = ({ count, to }: { count: number; to?: string }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const navigate = useNavigate();
  if (count <= 0) return null;
  return (
    <Tooltip
      title={t_i18n('This integration has {count} deployed instance(s). Manage them from the Deployed tab.', { values: { count } })}
      // Neutralize the global tooltip lowercasing: this is a full sentence.
      slotProps={{ popper: { sx: { textTransform: 'none' } } }}
    >
      <Chip
        icon={<CheckCircleOutlined sx={{ fontSize: 14 }} />}
        label={count > 1 ? t_i18n('{count} deployed', { values: { count } }) : t_i18n('Deployed')}
        size="small"
        variant="outlined"
        onClick={to
          ? (event) => {
            // The chip may live inside a clickable card: do not trigger it.
              event.stopPropagation();
              navigate(to);
            }
          : undefined}
        sx={{
          height: 24,
          fontSize: 11,
          fontWeight: 600,
          borderRadius: 1,
          color: theme.palette.success.main,
          borderColor: alpha(theme.palette.success.main, 0.4),
          backgroundColor: alpha(theme.palette.success.main, 0.08),
          '& .MuiChip-icon': { color: theme.palette.success.main },
          '&.MuiChip-clickable:hover': {
            backgroundColor: alpha(theme.palette.success.main, 0.16),
          },
        }}
      />
    </Tooltip>
  );
};

interface MarketplaceSectionHeaderProps {
  icon: SvgIconComponent;
  label: string;
  count: number;
  // When provided, the section can be collapsed from its header.
  collapsed?: boolean;
  onToggleCollapse?: () => void;
}

export const MarketplaceSectionHeader = ({ icon: Icon, label, count, collapsed = false, onToggleCollapse }: MarketplaceSectionHeaderProps) => {
  const theme = useTheme();
  return (
    <Stack
      direction="row"
      alignItems="center"
      gap={1.25}
      onClick={onToggleCollapse}
      sx={{
        marginBottom: collapsed ? 0 : 1.5,
        ...(onToggleCollapse && {
          cursor: 'pointer',
          userSelect: 'none',
        }),
      }}
    >
      <Box
        sx={{
          width: 28,
          height: 28,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          borderRadius: 1,
          border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
          backgroundColor: alpha(theme.palette.primary.main, 0.1),
        }}
      >
        <Icon sx={{ fontSize: 15, color: theme.palette.primary.main }} />
      </Box>
      <Typography
        component="h2"
        sx={{
          fontFamily: theme.typography.h1.fontFamily,
          fontSize: 16,
          fontWeight: 600,
        }}
      >
        {label}
      </Typography>
      <Box
        component="span"
        sx={{
          paddingInline: 0.75,
          paddingBlock: '1px',
          borderRadius: 0.5,
          backgroundColor: alpha(theme.palette.text.primary, 0.06),
          fontSize: 11,
          fontWeight: 500,
          fontVariantNumeric: 'tabular-nums',
          color: theme.palette.text.secondary,
        }}
      >
        {count}
      </Box>
      <Box sx={{ flex: 1, height: '1px', backgroundColor: alpha(theme.palette.text.primary, 0.05) }} />
      {onToggleCollapse && (
        <IconButton
          size="small"
          aria-expanded={!collapsed}
          aria-label={label}
        >
          <ExpandMoreOutlined
            fontSize="small"
            sx={{
              transition: 'transform 0.2s ease-in-out',
              transform: collapsed ? 'rotate(-90deg)' : 'none',
            }}
          />
        </IconButton>
      )}
    </Stack>
  );
};

export const ResultCountChip = ({ count }: { count: number }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  return (
    <Box
      component="span"
      sx={{
        marginLeft: 'auto',
        paddingInline: 1.25,
        paddingBlock: 0.5,
        borderRadius: 1,
        backgroundColor: alpha(theme.palette.text.primary, 0.06),
        fontSize: 13,
        fontWeight: 500,
        fontVariantNumeric: 'tabular-nums',
        color: theme.palette.text.secondary,
      }}
    >
      {(() => {
        if (count === 1) return t_i18n('1 result');
        return t_i18n('{count} results', { values: { count } });
      })()}
    </Box>
  );
};

interface MarketplaceEmptyStateProps {
  hasActiveFilters: boolean;
  onResetFilters: () => void;
  extraAction?: React.ReactNode;
}

export const MarketplaceEmptyState = ({ hasActiveFilters, onResetFilters, extraAction }: MarketplaceEmptyStateProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Stack
      justifyContent="center"
      alignItems="center"
      sx={{
        minHeight: '40vh',
      }}
    >
      <GradientCard sx={{
        px: 10,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: 4,
      }}
      >
        <Stack flexDirection="row" alignItems="flex-start" gap={1}>
          <GradientCard.Icon icon={Search} size="large" />
          <Stack>
            <GradientCard.Text sx={{ whiteSpace: 'pre' }}>{t_i18n('Sorry, we couldn\'t find any results for your search.')}</GradientCard.Text>
            <GradientCard.Text sx={{ whiteSpace: 'pre' }}>{t_i18n('For more results, you can search in the ecosystem.')}</GradientCard.Text>
          </Stack>
        </Stack>
        <Stack direction="row" gap={2}>
          {hasActiveFilters && (
            <Button variant="secondary" onClick={onResetFilters}>
              {t_i18n('Reset filters')}
            </Button>
          )}
          {extraAction}
        </Stack>
      </GradientCard>
    </Stack>
  );
};
