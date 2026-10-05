import React from 'react';
import { Box, Stack } from '@mui/material';
import {
  Checkbox,
  Combobox,
  ComboboxChips,
  ComboboxClear,
  ComboboxContent,
  ComboboxControls,
  ComboboxField,
  ComboboxInput,
  ComboboxLabel,
  ComboboxTrigger,
  Select,
  SelectContent,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import Filters from '../../common/lists/Filters';
import FilterIconButton from '../../../../components/FilterIconButton';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import { emptyFilterGroup, useAvailableFilterKeysForEntityTypes } from '../../../../utils/filters/filtersUtils';
import DefenseThreatsField from './DefenseThreatsField';
import {
  DEFENSE_LAYER_LABELS,
  DEFENSE_LAYERS,
  DEFENSE_THREAT_SCOPE_LABELS,
  DEFENSE_THREAT_SCOPE_MODES,
  DEFENSE_THREAT_TYPES,
  type DefenseLayersState,
  type DefenseScopeState,
  type DefenseThreatScopeMode,
  scopedDefensePlatforms,
} from './defenseMatrix-utils';

export interface DefensePlatformOption {
  readonly id: string;
  readonly name: string;
  readonly entity_type: string;
  readonly security_platform_type?: string | null;
}

interface PlatformOption {
  value: string;
  label: string;
  type: string;
}

interface DefenseScopeToolbarProps {
  platforms: ReadonlyArray<DefensePlatformOption>;
  scope: DefenseScopeState;
  onScopeChange: (scope: DefenseScopeState) => void;
  // Hides the platform selector, for views bound to one platform
  hidePlatforms?: boolean;
  layers?: DefenseLayersState;
  onLayersChange?: (layers: DefenseLayersState) => void;
}

const ThreatFilters = ({ scope, onScopeChange }: Pick<DefenseScopeToolbarProps, 'scope' | 'onScopeChange'>) => {
  const availableFilterKeys = useAvailableFilterKeysForEntityTypes(DEFENSE_THREAT_TYPES);
  const [filters, helpers] = useFiltersState(scope.threatFilters ?? emptyFilterGroup, emptyFilterGroup);
  const lastSent = React.useRef(JSON.stringify(scope.threatFilters ?? emptyFilterGroup));
  React.useEffect(() => {
    const serialized = JSON.stringify(filters);
    if (serialized !== lastSent.current) {
      lastSent.current = serialized;
      onScopeChange({ ...scope, threatFilters: filters });
    }
  }, [filters]);
  const searchContext = { entityTypes: DEFENSE_THREAT_TYPES };
  return (
    <Stack spacing={1} sx={{ minWidth: 260 }}>
      <Filters availableFilterKeys={availableFilterKeys} helpers={helpers} searchContext={searchContext} />
      <FilterIconButton filters={filters} helpers={helpers} searchContext={searchContext} redirection />
    </Stack>
  );
};

const DefenseScopeToolbar = ({
  platforms,
  scope,
  onScopeChange,
  hidePlatforms = false,
  layers,
  onLayersChange,
}: DefenseScopeToolbarProps) => {
  const { t_i18n } = useFormatter();
  const platformOptions: PlatformOption[] = platforms.map((p) => ({ value: p.id, label: p.name, type: p.entity_type }));
  const selectedPlatforms = platformOptions.filter((o) => scope.platformIds.includes(o.value));
  // A saved platform deleted or hidden since would scope every view to nothing while the selector reads "All platforms";
  // views bound to one platform pass no options
  React.useEffect(() => {
    if (hidePlatforms) return;
    const available = scopedDefensePlatforms(scope.platformIds, platforms).map((p) => p.id);
    if (available.length !== scope.platformIds.length) {
      onScopeChange({ ...scope, platformIds: available });
    }
  }, [hidePlatforms, platforms, scope.platformIds]);
  // The filter state is local: remount it when the threat filters change from outside (another user's stored scope),
  // never on its own edits
  const incomingFilters = JSON.stringify(scope.threatFilters ?? emptyFilterGroup);
  const [filtersSync, setFiltersSync] = React.useState({ value: incomingFilters, generation: 0 });
  if (incomingFilters !== filtersSync.value) {
    setFiltersSync({ value: incomingFilters, generation: filtersSync.generation + 1 });
  }
  const onThreatFiltersChange = (next: DefenseScopeState) => {
    setFiltersSync((current) => ({ ...current, value: JSON.stringify(next.threatFilters ?? emptyFilterGroup) }));
    onScopeChange(next);
  };

  return (
    <Box
      data-testid="defense-scope-toolbar"
      sx={{ display: 'flex', flexWrap: 'wrap', alignItems: 'flex-start', gap: 2 }}
    >
      {!hidePlatforms && (
        <Box sx={{ minWidth: 280, flex: '1 1 280px', maxWidth: 480 }}>
          <Combobox<PlatformOption>
            multiple
            className="w-full"
            options={platformOptions}
            value={selectedPlatforms}
            getOptionLabel={(option) => option.label}
            isOptionEqualToValue={(option, other) => option.value === other.value}
            onValueChange={(next) => onScopeChange({ ...scope, platformIds: ((next as PlatformOption[] | null) ?? []).map((o) => o.value) })}
            renderOption={(option) => (
              <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <ItemIcon type={option.type} />
                {option.label}
              </span>
            )}
          >
            <ComboboxLabel>{t_i18n('Security platforms')}</ComboboxLabel>
            <ComboboxField>
              <ComboboxChips aria-label={t_i18n('Security platforms')} />
              <ComboboxInput placeholder={t_i18n('All platforms')} data-testid="defense-platforms-input" />
              <ComboboxControls>
                <ComboboxClear />
                <ComboboxTrigger />
              </ComboboxControls>
            </ComboboxField>
            <ComboboxContent emptyMessage={t_i18n('No security platform')} listAriaLabel={t_i18n('Security platforms')} />
          </Combobox>
        </Box>
      )}
      <Box sx={{ minWidth: 200 }}>
        <Select
          value={scope.threatMode}
          onValueChange={(value) => onScopeChange({ ...scope, threatMode: value as DefenseThreatScopeMode })}
        >
          <SelectLabel>{t_i18n('Threat overlay')}</SelectLabel>
          <SelectTrigger aria-label={t_i18n('Threat overlay')} data-testid="defense-threat-mode">
            <SelectValue />
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Threat overlay')}>
            {DEFENSE_THREAT_SCOPE_MODES.map((mode) => (
              <SelectItem key={mode} value={mode}>{t_i18n(DEFENSE_THREAT_SCOPE_LABELS[mode])}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </Box>
      {scope.threatMode === 'SELECTED' && (
        <Box sx={{ minWidth: 280, flex: '1 1 280px', maxWidth: 480 }}>
          <DefenseThreatsField value={scope.threats} onChange={(threats) => onScopeChange({ ...scope, threats })} />
        </Box>
      )}
      {scope.threatMode === 'FILTERED' && <ThreatFilters key={filtersSync.generation} scope={scope} onScopeChange={onThreatFiltersChange} />}
      {layers && onLayersChange && (
        <Box role="group" aria-label={t_i18n('Layers')} sx={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 2, paddingTop: 3 }}>
          {DEFENSE_LAYERS.map((layer) => (
            <Checkbox
              key={layer}
              label={t_i18n(DEFENSE_LAYER_LABELS[layer])}
              checked={layers[layer]}
              data-testid={`defense-layer-${layer}`}
              onCheckedChange={(checked) => onLayersChange({ ...layers, [layer]: checked === true })}
            />
          ))}
        </Box>
      )}
    </Box>
  );
};

export default DefenseScopeToolbar;
