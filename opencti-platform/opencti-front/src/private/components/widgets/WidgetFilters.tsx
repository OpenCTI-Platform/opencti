import Filters from '@components/common/lists/Filters';
import React, { FunctionComponent, useEffect, useMemo } from 'react';
import { Box } from '@mui/material';
import { useTheme } from '@mui/styles';
import { Theme } from '../../../components/Theme';
import { useWidgetConfigContext } from '@components/widgets/WidgetConfigContext';
import useFiltersState from '../../../utils/filters/useFiltersState';
import { isFilterGroupNotEmpty, isDraftWorkspaceFilterGroup, useAvailableFilterKeysForEntityTypes } from '../../../utils/filters/filtersUtils';
import FilterIconButton from '../../../components/FilterIconButton';
import { useFormatter } from '../../../components/i18n';
import type { WidgetDataSelection, WidgetPerspective, WidgetVariableBinding } from '../../../utils/widget/widget';
import useHelper from '../../../utils/hooks/useHelper';
import { useDashboardVariables } from '../workspaces/dashboards/variables/DashboardVariablesContext';
import { FilterVariableSelectionProvider } from './FilterVariableSelectionContext';
import { FilterGroup } from '../../../utils/filters/filtersHelpers-types';

interface WidgetFiltersProps {
  perspective: WidgetPerspective | null;
  type: string;
  dataSelection: WidgetDataSelection;
  setDataSelection: (data: WidgetDataSelection) => void;
}

const WidgetFilters: FunctionComponent<WidgetFiltersProps> = ({ perspective, type, dataSelection, setDataSelection }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  // TODO(DRAFT_WORKFLOW): remove isDraftWorkflowEnabled and related checks when flag is removed
  const isDraftWorkflowEnabled = isFeatureEnable('DRAFT_WORKFLOW');
  const [filters, helpers] = useFiltersState(dataSelection.filters);
  const [filtersDynamicFrom, helpersDynamicFrom] = useFiltersState(dataSelection.dynamicFrom);
  const [filtersDynamicTo, helpersDynamicTo] = useFiltersState(dataSelection.dynamicTo);
  const { host } = useWidgetConfigContext();
  const { variables } = useDashboardVariables();

  const VARIABLE_SENTINEL_PREFIX = '__var__:';

  const collectVariableIds = (input: unknown, result: Set<string>) => {
    if (!input) {
      return;
    }
    if (typeof input === 'string') {
      if (input.startsWith(VARIABLE_SENTINEL_PREFIX)) {
        result.add(input.slice(VARIABLE_SENTINEL_PREFIX.length));
      }
      return;
    }
    if (Array.isArray(input)) {
      input.forEach((value) => collectVariableIds(value, result));
      return;
    }
    if (typeof input === 'object') {
      const obj = input as {
        values?: unknown;
        filters?: unknown;
        filterGroups?: unknown;
      };
      collectVariableIds(obj.values, result);
      collectVariableIds(obj.filters, result);
      collectVariableIds(obj.filterGroups, result);
    }
  };

  const extractVariableIdsFromFilterGroup = (filterGroup?: FilterGroup | null): Set<string> => {
    const result = new Set<string>();
    if (!filterGroup) {
      return result;
    }
    collectVariableIds(filterGroup, result);
    return result;
  };

  const hasVariableInFilters = useMemo(
    () => extractVariableIdsFromFilterGroup(filters).size > 0,
    [filters],
  );

  const computedVariableBindings = useMemo(() => {
    const ids = new Set<string>();
    extractVariableIdsFromFilterGroup(filters).forEach((id) => ids.add(id));
    extractVariableIdsFromFilterGroup(filtersDynamicFrom).forEach((id) => ids.add(id));
    extractVariableIdsFromFilterGroup(filtersDynamicTo).forEach((id) => ids.add(id));
    const bindings: WidgetVariableBinding[] = [];
    ids.forEach((variableId) => {
      const variable = variables.find((v) => v.id === variableId);
      if (!variable) {
        return;
      }
      bindings.push({
        variableId,
        variableName: variable.name,
        filterKeyType: variable.filterKeyType,
      });
    });
    return bindings;
  }, [filters, filtersDynamicFrom, filtersDynamicTo, variables]);

  useEffect(() => {
    setDataSelection({
      ...dataSelection,
      filters,
      dynamicTo: filtersDynamicTo,
      dynamicFrom: filtersDynamicFrom,
      variableBindings: computedVariableBindings,
    });
  }, [computedVariableBindings, filters, filtersDynamicFrom, filtersDynamicTo]);

  let availableEntityTypes;
  let searchContext;
  if (perspective === 'relationships') {
    searchContext = { entityTypes: ['stix-core-relationship', 'stix-sighting-relationship', 'contains', 'object-label'] };
  } else if (perspective === 'audits') {
    availableEntityTypes = ['History', 'Activity'];
    searchContext = { entityTypes: ['History'] };
  } else { // perspective = 'entities'
    availableEntityTypes = [
      'Stix-Domain-Object',
      'Stix-Cyber-Observable',
      ...(isDraftWorkflowEnabled ? ['DraftWorkspace'] : []),
    ];
    const isDraftWorkspaceOnly = isDraftWorkflowEnabled && isDraftWorkspaceFilterGroup(filters);
    searchContext = isDraftWorkspaceOnly
      ? { entityTypes: ['Stix-Core-Object', 'DraftWorkspace'] }
      : { entityTypes: ['Stix-Core-Object'] };
  }

  let availableFilterKeys = useAvailableFilterKeysForEntityTypes(searchContext.entityTypes);
  if (perspective !== 'relationships') {
    availableFilterKeys = availableFilterKeys.concat('entity_type');
  } else {
    availableFilterKeys = availableFilterKeys.filter((key) => key !== 'entity_type'); // for relationships perspective widget, use the relationship_type filter
  }

  const entitiesFilters = useAvailableFilterKeysForEntityTypes(['Stix-Core-Object']);

  const bookmarkAvailableEntityTypes = ['Malware', 'Threat-Actor-Individual', 'Threat-Actor-Group', 'Intrusion-Set', 'Campaign'];

  const handleVariableSelectedInFilter = () => {};

  return (
    <FilterVariableSelectionProvider onVariableSelected={handleVariableSelectedInFilter}>
    <>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', paddingTop: 2 }}>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Filters
            availableFilterKeys={type === 'bookmark' ? ['entity_type'] : availableFilterKeys}
            availableEntityTypes={availableEntityTypes}
            helpers={helpers}
            searchContext={type === 'bookmark' ? undefined : searchContext}
          />
        </Box>

        {perspective === 'relationships' && (
          <>
            <Box sx={{ display: 'flex', gap: 1 }}>
              <Filters
                availableFilterKeys={entitiesFilters}
                availableEntityTypes={[
                  'Stix-Domain-Object',
                  'Stix-Cyber-Observable',
                ]}
                helpers={helpersDynamicFrom}
                type="from"
                searchContext={{ entityTypes: ['Stix-Core-Object'] }}
              />
            </Box>
            <Box sx={{ display: 'flex', gap: 1 }}>
              <Filters
                availableFilterKeys={entitiesFilters}
                availableEntityTypes={[
                  'Stix-Domain-Object',
                  'Stix-Cyber-Observable',
                ]}
                helpers={helpersDynamicTo}
                type="to"
                searchContext={{ entityTypes: ['Stix-Core-Object'] }}
              />
            </Box>
          </>
        )}
      </Box>

      <Box sx={{ paddingTop: 1 }}>
        {isFilterGroupNotEmpty(filtersDynamicFrom) && (
          <div style={{ marginTop: 8, color: 'orange', marginBottom: 4 }}>
            {t_i18n('Pre-query to get data to be used as source entity of the relationship (limited to 5000)')}
          </div>
        )}
        <FilterIconButton
          filters={filtersDynamicFrom}
          helpers={helpersDynamicFrom}
          chipColor="warning"
          entityTypes={['Stix-Core-Object']}
          searchContext={searchContext}
          availableEntityTypes={[
            'Stix-Domain-Object',
            'Stix-Cyber-Observable',
          ]}
          host={host}
        />

        {isFilterGroupNotEmpty(filtersDynamicTo)
          && (
            <div style={{ marginTop: 8, color: theme.palette.success.main, marginBottom: 4 }}>
              {t_i18n('Pre-query to get data to be used as target entity of the relationship (limited to 5000)')}
            </div>
          )
        }
        <FilterIconButton
          filters={filtersDynamicTo}
          helpers={helpersDynamicTo}
          chipColor="success"
          entityTypes={['Stix-Core-Object']}
          searchContext={searchContext}
          availableEntityTypes={[
            'Stix-Domain-Object',
            'Stix-Cyber-Observable',
          ]}
          host={host}
        />

        {isFilterGroupNotEmpty(filters) && perspective === 'relationships' && (
          <div style={{ marginTop: 8, marginBottom: 4 }}>
            {t_i18n('Result: the relationships with source respecting the source pre-query, target respecting the target pre-query, and matching:')}
          </div>
        )}
        <FilterIconButton
          filters={filters}
          helpers={helpers}
          chipColor={hasVariableInFilters ? 'primary' : undefined}
          searchContext={searchContext}
          availableEntityTypes={type === 'bookmark' ? bookmarkAvailableEntityTypes : availableEntityTypes}
          entityTypes={searchContext.entityTypes}
          host={host}
        />
      </Box>
    </>
    </FilterVariableSelectionProvider>
  );
};

export default WidgetFilters;
