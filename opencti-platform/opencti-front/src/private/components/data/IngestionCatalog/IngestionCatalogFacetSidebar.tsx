import React, { Dispatch, SetStateAction } from 'react';
import { alpha, useTheme } from '@mui/material/styles';
import { Box, ButtonBase, Stack, Typography } from '@mui/material';
import { Check } from '@mui/icons-material';
import type { SvgIconComponent } from '@mui/icons-material';
import Button from '@common/button/Button';
import { getConnectorMetadata, getConnectorTypeIcon, IngestionConnectorType } from '@components/data/IngestionCatalog/utils/ingestionConnectorTypeMetadata';
import { CATALOG_STATUS_FACETS, CatalogFilterState, CatalogStatusFacet } from '@components/data/IngestionCatalog/hooks/useIngestionCatalogFilters';
import { useFormatter } from '../../../../components/i18n';

export const useCatalogStatusLabel = () => {
  const { t_i18n } = useFormatter();
  return (status: CatalogStatusFacet): string => {
    if (status === 'verified') return t_i18n('Verified by Filigran');
    if (status === 'deployed') return t_i18n('Deployed');
    return t_i18n('Playbook supported');
  };
};

interface FacetCheckboxProps {
  checked: boolean;
  label: string;
  count: number;
  icon?: SvgIconComponent;
  onToggle: () => void;
}

const FacetCheckbox = ({ checked, label, count, icon: Icon, onToggle }: FacetCheckboxProps) => {
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
      <Typography
        variant="body2"
        sx={{
          flex: 1,
          minWidth: 0,
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
          fontSize: 12,
          fontWeight: checked ? 500 : 400,
          color: checked ? theme.palette.text.primary : theme.palette.text.secondary,
        }}
      >
        {label}
      </Typography>
      <Box
        component="span"
        sx={{
          flexShrink: 0,
          paddingInline: 0.75,
          paddingBlock: '1px',
          borderRadius: 0.5,
          backgroundColor: alpha(theme.palette.text.primary, 0.06),
          fontSize: 10,
          fontVariantNumeric: 'tabular-nums',
          color: theme.palette.text.secondary,
        }}
      >
        {count}
      </Box>
    </ButtonBase>
  );
};

const FacetGroupLabel = ({ children }: { children: React.ReactNode }) => {
  const theme = useTheme();
  return (
    <Typography
      sx={{
        paddingInline: 1,
        fontFamily: theme.typography.h1.fontFamily,
        fontSize: 11,
        fontWeight: 600,
        letterSpacing: '0.12em',
        textTransform: 'uppercase',
        color: theme.palette.text.secondary,
      }}
    >
      {children}
    </Typography>
  );
};

const toggleValue = <T,>(list: T[], value: T): T[] => {
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
    <Box
      component="aside"
      sx={{
        width: 250,
        flexShrink: 0,
        position: 'sticky',
        top: theme.spacing(2),
        maxHeight: `calc(100vh - ${theme.spacing(20)})`,
        overflowY: 'auto',
      }}
    >
      <Box
        sx={{
          display: 'flex',
          flexDirection: 'column',
          gap: 2,
          padding: 2,
          borderRadius: 1,
          border: `1px solid ${alpha(theme.palette.text.primary, 0.08)}`,
          backgroundColor: theme.palette.background.paper,
        }}
      >
        <Stack direction="row" alignItems="center" justifyContent="space-between">
          <Typography
            sx={{
              fontFamily: theme.typography.h1.fontFamily,
              fontSize: 14,
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
