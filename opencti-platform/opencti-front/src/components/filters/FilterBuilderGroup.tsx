import React, { FunctionComponent, SyntheticEvent, useState } from 'react';
import Box from '@mui/material/Box';
import Chip from '@mui/material/Chip';
import TextField from '@mui/material/TextField';
import MUIAutocomplete from '@mui/material/Autocomplete';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import Typography from '@mui/material/Typography';
import Tooltip from '@mui/material/Tooltip';
import { AddOutlined, CloseOutlined } from '@mui/icons-material';
import { useTheme, alpha } from '@mui/material/styles';
import type { Theme } from '@mui/material/styles/createTheme';
import { useFormatter } from '../i18n';
import { FilterChipPopover, FilterChipsParameter, OperatorKeyValues } from './FilterChipPopover';
import { FilterRepresentative } from './FiltersModel';
import { Filter, FilterGroup, handleFilterHelpers } from '../../utils/filters/filtersHelpers-types';
import { FilterGroupPath } from '../../utils/filters/filterBuilderUtils';
import {
  FilterSearchContext,
  getAvailableOperatorForFilter,
  getDefaultFilterObject,
  getDefaultOperatorFilter,
  getFilterDefinitionFromFilterKeysMap,
  useBuildFilterKeysMapFromEntityType,
} from '../../utils/filters/filtersUtils';

interface FilterBuilderGroupProps {
  group: FilterGroup;
  path: FilterGroupPath;
  flatFilters: Filter[];
  helpers: handleFilterHelpers;
  filtersRepresentativesMap: Map<string, FilterRepresentative>;
  entityTypes: string[];
  availableFilterKeys: string[];
  availableEntityTypes?: string[];
  availableRelationshipTypes?: string[];
  availableRelationFilterTypes?: Record<string, string[]>;
  searchContext?: FilterSearchContext;
  onSetMode: (path: FilterGroupPath, mode: string) => void;
  onAddFilter: (path: FilterGroupPath, filter: Filter) => void;
  onAddGroup: (path: FilterGroupPath) => void;
  onRemoveGroup: (path: FilterGroupPath) => void;
  onRemoveFilter: (id: string) => void;
  onChangeFilterKey: (id: string, key: string, operator: string) => void;
}

const NO_VALUE_OPERATORS = ['nil', 'not_nil'];

const FilterBuilderGroup: FunctionComponent<FilterBuilderGroupProps> = ({
  group,
  path,
  flatFilters,
  helpers,
  filtersRepresentativesMap,
  entityTypes,
  availableFilterKeys,
  availableEntityTypes,
  availableRelationshipTypes,
  availableRelationFilterTypes,
  searchContext,
  onSetMode,
  onAddFilter,
  onAddGroup,
  onRemoveGroup,
  onRemoveFilter,
  onChangeFilterKey,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const isRoot = path.length === 0;
  const mode = group.mode ?? 'and';
  const accent = theme.palette.primary.main;

  const filterKeysMap = useBuildFilterKeysMapFromEntityType(entityTypes);
  const [chipParams, setChipParams] = useState<FilterChipsParameter>({
    filterId: undefined,
    anchorEl: undefined,
    anchorPosition: undefined,
  });

  const handleOpenChip = (event: SyntheticEvent, filterId?: string) => {
    const rect = (event.currentTarget as HTMLElement).getBoundingClientRect();
    setChipParams({
      filterId,
      anchorEl: event.currentTarget as HTMLElement,
      anchorPosition: { top: rect.bottom, left: rect.left },
    });
  };
  const handleCloseChip = () => setChipParams({ filterId: undefined, anchorEl: undefined, anchorPosition: undefined });

  const options = availableFilterKeys
    .map((key) => {
      const filterDefinition = getFilterDefinitionFromFilterKeysMap(key, filterKeysMap);
      return { value: key, label: t_i18n(filterDefinition?.label ?? key) };
    })
    .sort((a, b) => a.label.localeCompare(b.label));

  const handleAddCondition = () => {
    const firstKey = options[0]?.value ?? availableFilterKeys[0];
    if (!firstKey) return;
    const filterDefinition = getFilterDefinitionFromFilterKeysMap(firstKey, filterKeysMap);
    onAddFilter(path, getDefaultFilterObject(firstKey, filterDefinition));
  };

  const handleChangeKey = (id: string, newKey: string) => {
    const filterDefinition = getFilterDefinitionFromFilterKeysMap(newKey, filterKeysMap);
    onChangeFilterKey(id, newKey, getDefaultOperatorFilter(filterDefinition));
  };

  // Segmented AND / OR control shown in the group header.
  const renderModeToggle = () => (
    <Box sx={{ display: 'inline-flex', borderRadius: '6px', overflow: 'hidden', border: `1px solid ${theme.palette.divider}` }}>
      {['and', 'or'].map((m) => {
        const active = mode === m;
        return (
          <Box
            key={m}
            component="button"
            type="button"
            onClick={() => onSetMode(path, m)}
            sx={{
              border: 'none',
              cursor: 'pointer',
              minWidth: 40,
              padding: '3px 10px',
              fontSize: '0.68rem',
              fontWeight: 700,
              letterSpacing: '0.06em',
              textTransform: 'uppercase',
              color: active ? theme.palette.getContrastText(accent) : theme.palette.text.secondary,
              backgroundColor: active ? accent : 'transparent',
              transition: 'background-color 120ms ease',
              '&:hover': { backgroundColor: active ? accent : theme.palette.action.hover },
            }}
          >
            {t_i18n(m)}
          </Box>
        );
      })}
    </Box>
  );

  const renderValueCell = (filter: Filter) => {
    if (NO_VALUE_OPERATORS.includes(filter.operator ?? '')) {
      return (
        <Box sx={{ flexGrow: 1, minWidth: 0, display: 'flex', alignItems: 'center', color: 'text.disabled', fontStyle: 'italic', fontSize: '0.8rem' }}>
          {t_i18n('No value required')}
        </Box>
      );
    }
    return (
      <Box
        sx={{
          flexGrow: 1,
          minWidth: 0,
          display: 'flex',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '6px',
          minHeight: 34,
          padding: '3px 6px',
          borderRadius: '6px',
          border: `1px solid ${theme.palette.divider}`,
          backgroundColor: theme.palette.background.paper,
        }}
      >
        {filter.values.map((value: string) => (
          <Chip
            key={value}
            size="small"
            label={filtersRepresentativesMap.get(value)?.value ?? value}
            onDelete={() => helpers.handleRemoveRepresentationFilter(filter.id ?? '', value)}
            sx={{ borderRadius: '4px', height: 22, fontSize: '0.75rem' }}
          />
        ))}
        <Tooltip title={t_i18n('Add a value')}>
          {filter.values.length === 0 ? (
            <Box
              component="button"
              type="button"
              onClick={(event: SyntheticEvent) => handleOpenChip(event, filter.id)}
              sx={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '4px',
                cursor: 'pointer',
                border: `1px dashed ${theme.palette.divider}`,
                borderRadius: '4px',
                backgroundColor: 'transparent',
                color: 'text.secondary',
                padding: '2px 8px',
                fontSize: '0.75rem',
                '&:hover': { borderColor: accent, color: accent },
              }}
            >
              <AddOutlined sx={{ fontSize: 14 }} />
              {t_i18n('Add a value')}
            </Box>
          ) : (
            <Box
              component="button"
              type="button"
              onClick={(event: SyntheticEvent) => handleOpenChip(event, filter.id)}
              sx={{
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                cursor: 'pointer',
                width: 22,
                height: 22,
                border: `1px dashed ${theme.palette.divider}`,
                borderRadius: '4px',
                backgroundColor: 'transparent',
                color: 'text.secondary',
                padding: 0,
                '&:hover': { borderColor: accent, color: accent },
              }}
            >
              <AddOutlined sx={{ fontSize: 14 }} />
            </Box>
          )}
        </Tooltip>
      </Box>
    );
  };

  const renderConditionRow = (filter: Filter) => {
    const filterDefinition = getFilterDefinitionFromFilterKeysMap(filter.key, filterKeysMap);
    const isStixFiltering = entityTypes?.includes('Stix-Filtering');
    const availableOperators = getAvailableOperatorForFilter(filterDefinition, undefined, { isStixFiltering });
    const currentKeyOption = options.find((o) => o.value === filter.key)
      ?? { value: filter.key, label: t_i18n(filterDefinition?.label ?? filter.key) };
    return (
      <Box key={filter.id} sx={{ display: 'flex', alignItems: 'center', gap: theme.spacing(0.75) }}>
        <MUIAutocomplete
          options={options}
          disableClearable
          sx={{ width: 180, flexShrink: 0 }}
          value={currentKeyOption}
          isOptionEqualToValue={(o, v) => o.value === v.value}
          getOptionLabel={(o) => o.label}
          onChange={(_, selected) => {
            if (selected?.value && selected.value !== filter.key) handleChangeKey(filter.id ?? '', selected.value);
          }}
          renderInput={(params) => <TextField {...params} variant="outlined" size="small" sx={{ '& .MuiInputBase-input': { fontSize: '0.8rem' } }} />}
          renderOption={(props, option) => <li {...props} key={option.value}>{option.label}</li>}
        />
        <Select
          size="small"
          variant="outlined"
          value={availableOperators.includes(filter.operator ?? '') ? filter.operator : (availableOperators[0] ?? 'eq')}
          onChange={(event) => helpers.handleChangeOperatorFilters?.(filter.id ?? '', event.target.value)}
          sx={{ width: 150, flexShrink: 0, fontSize: '0.8rem' }}
        >
          {availableOperators.map((op) => (
            <MenuItem key={op} value={op} sx={{ fontSize: '0.8rem' }}>{t_i18n(OperatorKeyValues[op] ?? op)}</MenuItem>
          ))}
        </Select>
        {renderValueCell(filter)}
        <Tooltip title={t_i18n('Remove condition')}>
          <Box
            component="button"
            type="button"
            onClick={() => onRemoveFilter(filter.id ?? '')}
            sx={{
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              cursor: 'pointer',
              flexShrink: 0,
              width: 26,
              height: 26,
              padding: 0,
              border: 'none',
              borderRadius: '6px',
              color: 'text.secondary',
              backgroundColor: 'transparent',
              '&:hover': { color: theme.palette.error.main, backgroundColor: theme.palette.action.hover },
            }}
          >
            <CloseOutlined sx={{ fontSize: 16 }} />
          </Box>
        </Tooltip>
      </Box>
    );
  };

  const hasMembers = group.filters.length > 0 || group.filterGroups.length > 0;

  return (
    <Box
      sx={{
        position: 'relative',
        borderRadius: '8px',
        paddingTop: isRoot ? 0 : theme.spacing(1),
        paddingBottom: isRoot ? 0 : theme.spacing(1),
        paddingRight: 0,
        paddingLeft: isRoot ? 0 : theme.spacing(2),
        borderLeft: isRoot ? 'none' : `1px solid ${alpha(accent, 0.35)}`,
        marginLeft: isRoot ? 0 : theme.spacing(0.5),
      }}
    >
      {/* Group header */}
      <Box sx={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), marginBottom: theme.spacing(1) }}>
        {renderModeToggle()}
        <Typography variant="caption" sx={{ color: 'text.secondary' }}>
          {mode === 'and' ? t_i18n('match all group') : t_i18n('match any group')}
        </Typography>
        <Box sx={{ flexGrow: 1 }} />
        <Box
          component="button"
          type="button"
          onClick={handleAddCondition}
          sx={{
            cursor: 'pointer',
            border: `1px solid ${theme.palette.divider}`,
            borderRadius: '6px',
            backgroundColor: theme.palette.background.paper,
            color: 'text.primary',
            padding: '3px 8px',
            fontSize: '0.72rem',
            '&:hover': { borderColor: accent },
          }}
        >
          {t_i18n('+ Condition')}
        </Box>
        <Box
          component="button"
          type="button"
          onClick={() => onAddGroup(path)}
          sx={{
            cursor: 'pointer',
            border: `1px solid ${theme.palette.divider}`,
            borderRadius: '6px',
            backgroundColor: theme.palette.background.paper,
            color: 'text.primary',
            padding: '3px 8px',
            fontSize: '0.72rem',
            '&:hover': { borderColor: accent },
          }}
        >
          {t_i18n('+ Group')}
        </Box>
        {!isRoot && (
          <Tooltip title={t_i18n('Remove group')}>
            <Box
              component="button"
              type="button"
              onClick={() => onRemoveGroup(path)}
              sx={{
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                cursor: 'pointer',
                width: 26,
                height: 26,
                padding: 0,
                border: 'none',
                borderRadius: '6px',
                color: theme.palette.getContrastText(theme.palette.error.main),
                backgroundColor: theme.palette.error.main,
                '&:hover': { backgroundColor: theme.palette.error.dark },
              }}
            >
              <CloseOutlined sx={{ fontSize: 16 }} />
            </Box>
          </Tooltip>
        )}
      </Box>

      {/* Members */}
      {hasMembers ? (
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1) }}>
          {[
            ...group.filters.map((filter) => ({ key: filter.id ?? '', node: renderConditionRow(filter) })),
            ...group.filterGroups.map((subGroup, index) => ({
              key: `group-${index}`,
              node: (
                <FilterBuilderGroup
                  group={subGroup}
                  path={[...path, index]}
                  flatFilters={flatFilters}
                  helpers={helpers}
                  filtersRepresentativesMap={filtersRepresentativesMap}
                  entityTypes={entityTypes}
                  availableFilterKeys={availableFilterKeys}
                  availableEntityTypes={availableEntityTypes}
                  availableRelationshipTypes={availableRelationshipTypes}
                  availableRelationFilterTypes={availableRelationFilterTypes}
                  searchContext={searchContext}
                  onSetMode={onSetMode}
                  onAddFilter={onAddFilter}
                  onAddGroup={onAddGroup}
                  onRemoveGroup={onRemoveGroup}
                  onRemoveFilter={onRemoveFilter}
                  onChangeFilterKey={onChangeFilterKey}
                />
              ),
            })),
          ].map((member, index) => (
            <React.Fragment key={member.key}>
              {index > 0 && (
                <Box
                  component="span"
                  sx={{
                    alignSelf: 'flex-start',
                    textTransform: 'uppercase',
                    fontSize: '0.62rem',
                    fontWeight: 700,
                    letterSpacing: '0.08em',
                    color: 'text.disabled',
                    paddingLeft: theme.spacing(0.5),
                  }}
                >
                  {t_i18n(mode)}
                </Box>
              )}
              {member.node}
            </React.Fragment>
          ))}
        </Box>
      ) : (
        <Typography variant="body2" sx={{ color: 'text.disabled', fontStyle: 'italic', paddingY: theme.spacing(0.5) }}>
          {t_i18n('No condition yet — add a condition or a nested group.')}
        </Typography>
      )}

      {chipParams.filterId && (
        <FilterChipPopover
          params={chipParams}
          handleClose={handleCloseChip}
          open={Boolean(chipParams.filterId)}
          filters={flatFilters}
          helpers={helpers}
          availableRelationFilterTypes={availableRelationFilterTypes}
          availableEntityTypes={availableEntityTypes}
          availableRelationshipTypes={availableRelationshipTypes}
          filtersRepresentativesMap={filtersRepresentativesMap}
          entityTypes={entityTypes}
          searchContext={searchContext}
          hideOperatorSelect
        />
      )}
    </Box>
  );
};

export default FilterBuilderGroup;
