import React, { Fragment, FunctionComponent, SyntheticEvent, useState } from 'react';
import Box from '@mui/material/Box';
import Chip from '@mui/material/Chip';
import IconButton from '@mui/material/IconButton';
import TextField from '@mui/material/TextField';
import MUIAutocomplete from '@mui/material/Autocomplete';
import Button from '@mui/material/Button';
import Typography from '@mui/material/Typography';
import Tooltip from '@mui/material/Tooltip';
import { CreateNewFolderOutlined, DeleteOutlined } from '@mui/icons-material';
import { useTheme } from '@mui/material/styles';
import type { Theme } from '@mui/material/styles/createTheme';
import { useFormatter } from '../i18n';
import { FilterChipPopover, FilterChipsParameter } from './FilterChipPopover';
import { FilterRepresentative } from './FiltersModel';
import { Filter, FilterGroup, handleFilterHelpers } from '../../utils/filters/filtersHelpers-types';
import { FilterGroupPath } from '../../utils/filters/filterBuilderUtils';
import { FilterSearchContext, getDefaultFilterObject, getFilterDefinitionFromFilterKeysMap, useBuildFilterKeysMapFromEntityType } from '../../utils/filters/filtersUtils';

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
}

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
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const isRoot = path.length === 0;
  const mode = group.mode ?? 'and';
  // Alternate the accent colour with the nesting depth for readability.
  const accentColor = path.length % 2 === 0 ? theme.palette.primary.main : theme.palette.secondary.main;

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

  const toggleMode = () => onSetMode(path, mode === 'and' ? 'or' : 'and');

  const options = availableFilterKeys
    .map((key) => {
      const filterDefinition = getFilterDefinitionFromFilterKeysMap(key, filterKeysMap);
      return { value: key, label: t_i18n(filterDefinition?.label ?? key) };
    })
    .sort((a, b) => a.label.localeCompare(b.label));

  const handleAddFilterKey = (key: string) => {
    const filterDefinition = getFilterDefinitionFromFilterKeysMap(key, filterKeysMap);
    onAddFilter(path, getDefaultFilterObject(key, filterDefinition));
  };

  // Small clickable pill used both as the group header operator and as the
  // connector shown between two members. Toggles the group mode on click.
  const renderModePill = (interactive = true) => (
    <Tooltip title={interactive ? t_i18n('Click to switch AND / OR') : ''}>
      <Box
        component={interactive ? 'button' : 'div'}
        onClick={interactive ? toggleMode : undefined}
        sx={{
          border: 'none',
          cursor: interactive ? 'pointer' : 'default',
          textTransform: 'uppercase',
          fontFamily: 'Consolas, monaco, monospace',
          fontWeight: 700,
          fontSize: '0.7rem',
          letterSpacing: '0.08em',
          lineHeight: 1,
          padding: '5px 10px',
          borderRadius: '10px',
          color: theme.palette.getContrastText(accentColor),
          backgroundColor: accentColor,
          transition: 'opacity 120ms ease',
          '&:hover': { opacity: interactive ? 0.85 : 1 },
        }}
      >
        {t_i18n(mode)}
      </Box>
    </Tooltip>
  );

  const renderFilterChip = (filter: Filter) => {
    const filterDefinition = getFilterDefinitionFromFilterKeysMap(filter.key, filterKeysMap);
    const label = t_i18n(filterDefinition?.label ?? filter.key);
    const valuesLabel = filter.values.length > 0
      ? filter.values
          .map((v) => filtersRepresentativesMap.get(v)?.value ?? v)
          .join(filter.mode === 'and' ? ' & ' : ' | ')
      : t_i18n('Set a value…');
    const hasValue = filter.values.length > 0 || ['nil', 'not_nil'].includes(filter.operator ?? '');
    return (
      <Chip
        key={filter.id}
        variant="outlined"
        onClick={(event) => handleOpenChip(event, filter.id)}
        onDelete={() => onRemoveFilter(filter.id ?? '')}
        sx={{
          height: 'auto',
          borderRadius: '6px',
          borderColor: theme.palette.divider,
          backgroundColor: theme.palette.background.default,
          '& .MuiChip-label': { display: 'flex', alignItems: 'center', gap: '6px', padding: '6px 8px' },
        }}
        label={(
          <>
            <strong>{label}</strong>
            <Box
              component="span"
              sx={{
                fontFamily: 'Consolas, monaco, monospace',
                fontSize: '0.7rem',
                fontWeight: 700,
                padding: '2px 6px',
                borderRadius: '4px',
                backgroundColor: theme.palette.action.selected,
              }}
            >
              {filter.operator ?? 'eq'}
            </Box>
            <Box
              component="span"
              sx={{ color: hasValue ? 'text.primary' : 'text.disabled', fontStyle: hasValue ? 'normal' : 'italic' }}
            >
              {valuesLabel}
            </Box>
          </>
        )}
      />
    );
  };

  const members: React.ReactNode[] = [
    ...group.filters.map((filter) => renderFilterChip(filter)),
    ...group.filterGroups.map((subGroup, index) => (
      <FilterBuilderGroup

        key={`group-${index}`}
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
      />
    )),
  ];

  return (
    <Box
      sx={{
        position: 'relative',
        borderRadius: '8px',
        padding: theme.spacing(1.5),
        border: isRoot ? 'none' : `1px solid ${theme.palette.divider}`,
        borderLeft: isRoot ? 'none' : `3px solid ${accentColor}`,
        backgroundColor: isRoot ? 'transparent' : theme.palette.background.paper,
      }}
    >
      <Box sx={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), marginBottom: theme.spacing(1.5) }}>
        {renderModePill()}
        <Typography variant="caption" sx={{ color: 'text.secondary' }}>
          {mode === 'and' ? t_i18n('All conditions must match') : t_i18n('Any condition can match')}
        </Typography>
        <Box sx={{ flexGrow: 1 }} />
        {!isRoot && (
          <Tooltip title={t_i18n('Remove group')}>
            <IconButton size="small" onClick={() => onRemoveGroup(path)}>
              <DeleteOutlined fontSize="small" />
            </IconButton>
          </Tooltip>
        )}
      </Box>

      {members.length > 0 ? (
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', gap: theme.spacing(0.75) }}>
          {members.map((node, i) => (

            <Fragment key={i}>
              {i > 0 && (
                <Box sx={{ paddingLeft: theme.spacing(1.5) }}>{renderModePill()}</Box>
              )}
              {node}
            </Fragment>
          ))}
        </Box>
      ) : (
        <Typography variant="body2" sx={{ color: 'text.disabled', fontStyle: 'italic', paddingY: theme.spacing(0.5) }}>
          {t_i18n('No condition yet — add a filter or a nested group below.')}
        </Typography>
      )}

      <Box sx={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), marginTop: theme.spacing(1.5) }}>
        <MUIAutocomplete
          options={options}
          sx={{ width: 240 }}
          value={null}
          blurOnSelect
          onChange={(_, selected) => {
            if (selected?.value) handleAddFilterKey(selected.value);
          }}
          renderInput={(params) => (
            <TextField {...params} variant="outlined" size="small" label={t_i18n('Add filter')} />
          )}
          renderOption={(props, option) => <li {...props} key={option.value}>{option.label}</li>}
        />
        <Button
          size="small"
          color="primary"
          startIcon={<CreateNewFolderOutlined fontSize="small" />}
          onClick={() => onAddGroup(path)}
        >
          {t_i18n('Add group')}
        </Button>
      </Box>

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
        />
      )}
    </Box>
  );
};

export default FilterBuilderGroup;
