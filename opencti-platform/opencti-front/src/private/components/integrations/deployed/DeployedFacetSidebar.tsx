import React, { Dispatch, SetStateAction } from 'react';
import { alpha, useTheme } from '@mui/material/styles';
import { Box, Stack, Typography } from '@mui/material';
import { AutorenewOutlined, ExtensionOutlined, PauseCircleOutlined, PlayCircleOutlined, WidgetsOutlined } from '@mui/icons-material';
import type { SvgIconComponent } from '@mui/icons-material';
import Button from '@common/button/Button';
import { FacetCheckbox, FacetGroupLabel, toggleValue } from '@components/integrations/catalog/IngestionCatalogFacetSidebar';
import { getConnectorMetadata, getConnectorTypeIcon, IngestionConnectorType } from '@components/integrations/catalog/utils/ingestionConnectorTypeMetadata';
import { getBuiltInIntegration, isBuiltInIntegrationKind } from '@components/integrations/available/builtInIntegrations';
import {
  DEPLOYED_KIND_FACETS,
  DEPLOYED_STATUS_FACETS,
  DeployedFilterState,
  DeployedKindFacet,
  DeployedStatusFacet,
} from '@components/integrations/deployed/useDeployedIntegrationsFilters';
import { useFormatter } from '../../../../components/i18n';

const STATUS_FACET_ICONS: Record<DeployedStatusFacet, SvgIconComponent> = {
  active: PlayCircleOutlined,
  processing: AutorenewOutlined,
  inactive: PauseCircleOutlined,
};

const KIND_FACET_ICONS: Record<DeployedKindFacet, SvgIconComponent> = {
  connector: ExtensionOutlined,
  'built-in': WidgetsOutlined,
};

export const useDeployedTypeMetadata = () => {
  const { t_i18n } = useFormatter();
  return (sectionKey: string): { label: string; icon: SvgIconComponent } => {
    if (isBuiltInIntegrationKind(sectionKey)) {
      const definition = getBuiltInIntegration(sectionKey);
      return {
        label: definition ? t_i18n(definition.label) : sectionKey,
        icon: definition ? definition.icon : WidgetsOutlined,
      };
    }
    return {
      label: getConnectorMetadata(sectionKey as IngestionConnectorType, t_i18n).label,
      icon: getConnectorTypeIcon(sectionKey),
    };
  };
};

interface DeployedFacetSidebarProps {
  filters: DeployedFilterState;
  onFiltersChange: Dispatch<SetStateAction<DeployedFilterState>>;
  hasActiveFilters: boolean;
  onClearAll: () => void;
  facets: {
    types: string[];
    typeCounts: Record<string, number>;
    statusCounts: Record<string, number>;
    kindCounts: Record<string, number>;
  };
}

const DeployedFacetSidebar = ({
  filters,
  onFiltersChange,
  hasActiveFilters,
  onClearAll,
  facets,
}: DeployedFacetSidebarProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const typeMetadata = useDeployedTypeMetadata();

  const statusLabel = (status: DeployedStatusFacet): string => {
    if (status === 'active') return t_i18n('Active');
    if (status === 'processing') return t_i18n('Processing');
    return t_i18n('Inactive');
  };

  const kindLabel = (kind: DeployedKindFacet): string => {
    return kind === 'connector' ? t_i18n('Connectors') : t_i18n('Built-in');
  };

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
          {DEPLOYED_KIND_FACETS.map((kind) => (
            <FacetCheckbox
              key={kind}
              checked={filters.kinds.includes(kind)}
              count={facets.kindCounts[kind] ?? 0}
              icon={KIND_FACET_ICONS[kind]}
              label={kindLabel(kind)}
              onToggle={() => onFiltersChange((prev) => ({ ...prev, kinds: toggleValue(prev.kinds, kind) }))}
            />
          ))}
        </Box>

        <Box sx={dividedGroupSx}>
          <FacetGroupLabel>{t_i18n('Type')}</FacetGroupLabel>
          {facets.types.map((type) => {
            const { label, icon } = typeMetadata(type);
            return (
              <FacetCheckbox
                key={type}
                checked={filters.types.includes(type)}
                count={facets.typeCounts[type] ?? 0}
                icon={icon}
                label={label}
                onToggle={() => onFiltersChange((prev) => ({ ...prev, types: toggleValue(prev.types, type) }))}
              />
            );
          })}
        </Box>

        <Box sx={dividedGroupSx}>
          <FacetGroupLabel>{t_i18n('Status')}</FacetGroupLabel>
          {DEPLOYED_STATUS_FACETS.map((status) => (
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

export default DeployedFacetSidebar;
