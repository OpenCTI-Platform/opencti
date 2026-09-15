import LibraryAddOutlinedIcon from '@mui/icons-material/LibraryAddOutlined';
import AddOutlined from '@mui/icons-material/AddOutlined';
import Box from '@mui/material/Box';
import Button from '@common/button/Button';
import Stack from '@mui/material/Stack';
import { IconButton, Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@filigran/design-system';
import { Fragment, FunctionComponent } from 'react';
import type { FilterGroup, handleFilterHelpers } from '../../../utils/filters/filtersHelpers-types';
import { FilterSearchContext, getDefaultFilterObject, getFilterDefinitionFromFilterKeysMap, useBuildFilterKeysMapFromEntityType } from '../../../utils/filters/filtersUtils';
import type { WidgetHost } from '../../../utils/widget/widget';
import { useFormatter } from '../../i18n';
import { FilterRepresentative } from '../FiltersModel';
import FilterRow from './FilterRow';
import { CloseOutlined } from '@mui/icons-material';

export interface FilterGroupPanelProps {
  /** The group to edit. Always a non-root group, so it always has an id (still handled defensively). */
  group: FilterGroup;
  helpers: handleFilterHelpers;
  availableFilterKeys: string[];
  entityTypes?: string[];
  filtersRepresentativesMap?: Map<string, FilterRepresentative>;
  availableEntityTypes?: string[];
  availableRelationshipTypes?: string[];
  availableRelationFilterTypes?: Record<string, string[]>;
  searchContext?: FilterSearchContext;
  host?: WidgetHost;
}

/**
 * Recursive editor of a nested filter group:
 * ┌─────────────────────────────────────────────┐
 * │ [AND ▾]            + Condition  Group   ✕   │
 * │ <FilterRow />                               │
 * │ AND                                         │
 * │ <FilterRow />                               │
 * │ ▏ <FilterGroupPanel /> (recursion, indented)│
 * └─────────────────────────────────────────────┘
 *
 * Layout mirrors the read-only FilterGroupsVisualDisplay (dark surface, 16px padding,
 * sub-groups indented) so both stay visually consistent.
 */
const FilterGroupPanel: FunctionComponent<FilterGroupPanelProps> = ({
  group,
  helpers,
  availableFilterKeys,
  entityTypes = ['Stix-Core-Object'],
  filtersRepresentativesMap = new Map(),
  availableEntityTypes,
  availableRelationshipTypes,
  availableRelationFilterTypes,
  searchContext,
  host,
}) => {
  const { t_i18n } = useFormatter();
  const filterKeysMap = useBuildFilterKeysMapFromEntityType(entityTypes);
  const groupId = group.id;
  const mode = (group.mode ?? 'and').toLowerCase();

  const handleChangeMode = (value: string) => {
    if (value.toLowerCase() === mode) return;
    helpers.handleSwitchGlobalMode(groupId);
  };

  const handleAddCondition = () => {
    const filterKey = availableFilterKeys[0];
    if (!filterKey) return;
    const filterDefinition = getFilterDefinitionFromFilterKeysMap(filterKey, filterKeysMap);
    helpers.handleAddFilterWithEmptyValue(getDefaultFilterObject(filterKey, filterDefinition), groupId);
  };

  return (
    <Box
      data-testid={`filter-group-panel-${groupId ?? 'root'}`}
      sx={{
        width: '100%',
      }}
    >
      <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ gap: 1, marginBottom: 1 }}>
        <Select value={mode} onValueChange={handleChangeMode}>
          <SelectTrigger
            id={`filter-group-mode-select-${groupId ?? 'root'}`}
            data-testid={`filter-group-mode-select-${groupId ?? 'root'}`}
            aria-label={t_i18n('Mode')}
            style={{ flexShrink: 0 }}
          >
            <SelectValue />
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Mode')}>
            <SelectItem value="and">{t_i18n('and').toUpperCase()}</SelectItem>
            <SelectItem value="or">{t_i18n('or').toUpperCase()}</SelectItem>
          </SelectContent>
        </Select>
        <Stack direction="row" alignItems="center" sx={{ gap: 1 }}>
          <Button
            variant="tertiary"
            size="small"
            startIcon={<AddOutlined fontSize="small" />}
            onClick={handleAddCondition}
            data-testid={`filter-group-add-condition-${groupId ?? 'root'}`}
          >
            {t_i18n('Condition')}
          </Button>
          <Button
            variant="tertiary"
            size="small"
            startIcon={<LibraryAddOutlinedIcon fontSize="small" />}
            onClick={() => helpers.handleAddFilterGroup(groupId)}
            data-testid={`filter-group-add-group-${groupId ?? 'root'}`}
          >
            {t_i18n('Group')}
          </Button>
          <IconButton
            priority="tertiary"
            variant="destructive"
            onClick={() => helpers.handleRemoveFilterGroup(groupId ?? '')}
            data-testid={`filter-group-remove-${groupId ?? 'root'}`}
            aria-label={t_i18n('Delete')}
            icon={<CloseOutlined fontSize="small" />}
          />
        </Stack>
      </Stack>
      <Stack sx={{ gap: 1 }}>
        {group.filters.length === 0 && (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
            {`${t_i18n('No rule apply')} - `}
            <Button
              variant="tertiary"
              onClick={handleAddCondition}
              data-testid={`filter-group-add-condition-link-${groupId ?? 'root'}`}
              sx={{ textDecoration: 'underline', padding: 0, minWidth: 'auto' }}
            >
              {t_i18n('add a filter rule')}
            </Button>
          </Box>
        )}
        {group.filters.map((filter, index) => (
          <Fragment key={filter.id ?? `${filter.key}-${index}`}>
            {index !== 0 && (
              <Box
                data-testid="filter-group-mode-separator"
                sx={{ textTransform: 'uppercase', fontWeight: 'bold' }}
              >
                {t_i18n(mode)}
              </Box>
            )}
            <FilterRow
              filter={filter}
              helpers={helpers}
              availableFilterKeys={availableFilterKeys}
              entityTypes={entityTypes}
              filtersRepresentativesMap={filtersRepresentativesMap}
              availableEntityTypes={availableEntityTypes}
              availableRelationshipTypes={availableRelationshipTypes}
              availableRelationFilterTypes={availableRelationFilterTypes}
              searchContext={searchContext}
              host={host}
            />
          </Fragment>
        ))}
      </Stack>
      {group.filterGroups.length > 0 && (
        <Stack sx={{ gap: 1, marginTop: 1 }}>
          {group.filterGroups.map((subGroup, index) => (
            <Box
              key={subGroup.id ?? `sub-group-${index}`}
              sx={{
                paddingLeft: 2,
                paddingY: 2,
                borderLeft: 2,
                borderColor: 'primary.main',
              }}
            >
              <FilterGroupPanel
                group={subGroup}
                helpers={helpers}
                availableFilterKeys={availableFilterKeys}
                entityTypes={entityTypes}
                filtersRepresentativesMap={filtersRepresentativesMap}
                availableEntityTypes={availableEntityTypes}
                availableRelationshipTypes={availableRelationshipTypes}
                availableRelationFilterTypes={availableRelationFilterTypes}
                searchContext={searchContext}
                host={host}
              />
            </Box>
          ))}
        </Stack>
      )}
    </Box>
  );
};

export default FilterGroupPanel;
