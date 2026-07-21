import React, { Dispatch, SetStateAction } from 'react';
import { alpha, useTheme } from '@mui/material/styles';
import { Box, ButtonBase, Stack, Tooltip, Typography } from '@mui/material';
import { Check, ExtensionOutlined, GroupsOutlined, VerifiedOutlined, WidgetsOutlined } from '@mui/icons-material';
import type { SvgIconComponent } from '@mui/icons-material';
import Button from '@common/button/Button';
import { getConnectorMetadata, getConnectorTypeIcon, IngestionConnectorType } from '@components/integrations/catalog/utils/ingestionConnectorTypeMetadata';
import { getUseCaseIcon } from '@components/integrations/catalog/utils/useCaseIcons';
import {
  CATALOG_DEPLOYMENT_FACETS,
  CATALOG_STATUS_FACETS,
  CatalogDeploymentFacet,
  CatalogFilterState,
  CatalogStatusFacet,
} from '@components/integrations/catalog/hooks/useIngestionCatalogFilters';
import { useFormatter } from '../../../../components/i18n';

export const useCatalogStatusLabel = () => {
  const { t_i18n } = useFormatter();
  return (status: CatalogStatusFacet): string => {
    if (status === 'filigran') return t_i18n('Supported by Filigran');
    return t_i18n('Supported by Community');
  };
};

const STATUS_FACET_ICONS: Record<CatalogStatusFacet, SvgIconComponent> = {
  filigran: VerifiedOutlined,
  community: GroupsOutlined,
};

export const useCatalogDeploymentLabel = () => {
  const { t_i18n } = useFormatter();
  return (deployment: CatalogDeploymentFacet): string => {
    if (deployment === 'connector') return t_i18n('Connectors');
    return t_i18n('Built-in');
  };
};

const DEPLOYMENT_FACET_ICONS: Record<CatalogDeploymentFacet, SvgIconComponent> = {
  connector: ExtensionOutlined,
  'built-in': WidgetsOutlined,
};

interface FacetCheckboxProps {
  checked: boolean;
  label: string;
  count: number;
  icon?: SvgIconComponent;
  onToggle: () => void;
}

export const FacetCheckbox = ({ checked, label, count, icon: Icon, onToggle }: FacetCheckboxProps) => {
  const theme = useTheme();
  const isDisabled = count === 0 && !checked;
  return (
    <ButtonBase
      role="checkbox"
      aria-checked={checked}
      aria-label={label}
      disabled={isDisabled}
      onClick={onToggle}
      sx={{
        width: '100%',
        display: 'flex',
        alignItems: 'center',
        gap: 1.25,
        textAlign: 'left',
        paddingInline: 1,
        paddingBlock: 0.75,
        borderRadius: 1,
        opacity: isDisabled ? 0.4 : 1,
        transition: 'background-color 0.2s ease-in-out',
        '&:hover': {
          backgroundColor: theme.palette.action.hover,
        },
      }}
    >
      <Box
        sx={{
          width: 16,
          height: 16,
          flexShrink: 0,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          borderRadius: 0.5,
          border: `1px solid ${checked ? theme.palette.primary.main : alpha(theme.palette.text.primary, 0.25)}`,
          backgroundColor: checked ? theme.palette.primary.main : 'transparent',
          boxShadow: checked ? `0 0 8px ${alpha(theme.palette.primary.main, 0.45)}` : 'none',
          transition: 'all 0.2s ease-in-out',
        }}
      >
        {checked && (
          <Check sx={{ fontSize: 12, color: theme.palette.primary.contrastText }} />
        )}
      </Box>
      {Icon && (
        <Icon
          sx={{
            fontSize: 15,
            flexShrink: 0,
            color: checked ? theme.palette.primary.main : theme.palette.text.secondary,
            transition: 'color 0.2s ease-in-out',
          }}
        />
      )}
      {/* Facet labels (especially use cases) can be longer than the sidebar
          width: the full value is exposed through a tooltip. */}
      <Tooltip title={label} placement="right">
        <Typography
          variant="body2"
          sx={{
            flex: 1,
            minWidth: 0,
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
            fontSize: 13,
            fontWeight: checked ? 500 : 400,
            color: checked ? theme.palette.text.primary : theme.palette.text.secondary,
          }}
        >
          {label}
        </Typography>
      </Tooltip>
      <Box
        component="span"
        sx={{
          flexShrink: 0,
          paddingInline: 0.75,
          paddingBlock: '1px',
          borderRadius: 0.5,
          backgroundColor: alpha(theme.palette.text.primary, 0.06),
          fontSize: 11,
          fontVariantNumeric: 'tabular-nums',
          color: theme.palette.text.secondary,
        }}
      >
        {count}
      </Box>
    </ButtonBase>
  );
};

// Sentence case: the V7 design language avoids all-caps text.
export const FacetGroupLabel = ({ children }: { children: React.ReactNode }) => {
  const theme = useTheme();
  return (
    <Typography
      sx={{
        paddingInline: 1,
        fontFamily: theme.typography.h1.fontFamily,
        fontSize: 12,
        fontWeight: 600,
        color: theme.palette.text.secondary,
      }}
    >
      {children}
    </Typography>
  );
};

export const toggleValue = <T,>(list: T[], value: T): T[] => {
  return list.includes(value) ? list.filter((v) => v !== value) : [...list, value];
};

interface IngestionCatalogFacetSidebarProps {
  filters: CatalogFilterState;
  onFiltersChange: Dispatch<SetStateAction<CatalogFilterState>>;
  hasActiveFilters: boolean;
  onClearAll: () => void;
  facets: {
    types: IngestionConnectorType[];
    useCases: string[];
    typeCounts: Record<string, number>;
    useCaseCounts: Record<string, number>;
    statusCounts: Record<string, number>;
    deploymentCounts: Record<string, number>;
  };
}

const IngestionCatalogFacetSidebar = ({
  filters,
  onFiltersChange,
  hasActiveFilters,
  onClearAll,
  facets,
}: IngestionCatalogFacetSidebarProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const statusLabel = useCatalogStatusLabel();
  const deploymentLabel = useCatalogDeploymentLabel();

  const groupSx = {
    display: 'flex',
    flexDirection: 'column',
    gap: 0.25,
  };
  const dividedGroupSx = {
    ...groupSx,
    borderTop: `1px solid ${alpha(theme.palette.text.primary, 0.05)}`,
    paddingTop: 2,
  };

  return (
    // Fixed sticky column on md+; below md the page stacks it full-width
    // above the cards (sticky + max-height are disabled so the filters do
    // not trap the whole viewport).
    <Box
      component="aside"
      sx={{
        width: { xs: '100%', md: 250 },
        flexShrink: 0,
        position: { xs: 'static', md: 'sticky' },
        top: theme.spacing(2),
      }}
    >
      {/* The scroll happens on an inner box: overflow on the sticky element
          itself breaks sticky positioning in WebKit. */}
      <Box
        sx={{
          display: 'flex',
          flexDirection: 'column',
          gap: 2,
          padding: 2,
          borderRadius: 1,
          border: `1px solid ${alpha(theme.palette.text.primary, 0.08)}`,
          backgroundColor: theme.palette.background.paper,
          maxHeight: { xs: 'none', md: `calc(100vh - ${theme.spacing(20)})` },
          overflowY: { xs: 'visible', md: 'auto' },
        }}
      >
        <Stack direction="row" alignItems="center" justifyContent="space-between">
          <Typography
            sx={{
              fontFamily: theme.typography.h1.fontFamily,
              fontSize: 15,
              fontWeight: 600,
            }}
          >
            {t_i18n('Filters')}
          </Typography>
          {hasActiveFilters && (
            <Button
              variant="tertiary"
              size="small"
              onClick={onClearAll}
            >
              {t_i18n('Clear all')}
            </Button>
          )}
        </Stack>

        <Box sx={groupSx}>
          <FacetGroupLabel>{t_i18n('Kind')}</FacetGroupLabel>
          {CATALOG_DEPLOYMENT_FACETS.map((deployment) => (
            <FacetCheckbox
              key={deployment}
              checked={filters.deployments.includes(deployment)}
              count={facets.deploymentCounts[deployment] ?? 0}
              icon={DEPLOYMENT_FACET_ICONS[deployment]}
              label={deploymentLabel(deployment)}
              onToggle={() => onFiltersChange((prev) => ({ ...prev, deployments: toggleValue(prev.deployments, deployment) }))}
            />
          ))}
        </Box>

        <Box sx={dividedGroupSx}>
          <FacetGroupLabel>{t_i18n('Connector type')}</FacetGroupLabel>
          {facets.types.map((type) => (
            <FacetCheckbox
              key={type}
              checked={filters.types.includes(type)}
              count={facets.typeCounts[type] ?? 0}
              icon={getConnectorTypeIcon(type)}
              label={getConnectorMetadata(type, t_i18n).label}
              onToggle={() => onFiltersChange((prev) => ({ ...prev, types: toggleValue(prev.types, type) }))}
            />
          ))}
        </Box>

        {facets.useCases.length > 0 && (
          <Box sx={dividedGroupSx}>
            <FacetGroupLabel>{t_i18n('Use cases')}</FacetGroupLabel>
            {facets.useCases.map((useCase) => (
              <FacetCheckbox
                key={useCase}
                checked={filters.useCases.includes(useCase)}
                count={facets.useCaseCounts[useCase] ?? 0}
                icon={getUseCaseIcon(useCase)}
                label={useCase} // no translation on purpose, values come from the catalog
                onToggle={() => onFiltersChange((prev) => ({ ...prev, useCases: toggleValue(prev.useCases, useCase) }))}
              />
            ))}
          </Box>
        )}

        <Box sx={dividedGroupSx}>
          <FacetGroupLabel>{t_i18n('Status')}</FacetGroupLabel>
          {CATALOG_STATUS_FACETS.map((status) => (
            <FacetCheckbox
              key={status}
              checked={filters.statuses.includes(status)}
              count={facets.statusCounts[status] ?? 0}
              icon={STATUS_FACET_ICONS[status]}
              label={statusLabel(status)}
              onToggle={() => onFiltersChange((prev) => ({ ...prev, statuses: toggleValue(prev.statuses, status) }))}
            />
          ))}
        </Box>
      </Box>
    </Box>
  );
};

export default IngestionCatalogFacetSidebar;
