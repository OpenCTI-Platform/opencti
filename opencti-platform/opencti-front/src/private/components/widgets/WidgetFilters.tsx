import Filters from '@components/common/lists/Filters';
import React, { FunctionComponent, useEffect, useState } from 'react';
import { Box } from '@mui/material';
import { useTheme } from '@mui/styles';
import { Theme } from '../../../components/Theme';
import { useWidgetConfigContext } from '@components/widgets/WidgetConfigContext';
import useFiltersState from '../../../utils/filters/useFiltersState';
import { isDraftWorkspaceFilterGroup, isFilterGroupNotEmpty, useAvailableFilterKeysForEntityTypes } from '../../../utils/filters/filtersUtils';
import FilterIconButton from '../../../components/FilterIconButton';
import { useFormatter } from '../../../components/i18n';
import type { WidgetDataSelection, WidgetPerspective } from '../../../utils/widget/widget';
import useHelper from '../../../utils/hooks/useHelper';
import WidgetSavedFiltersSelection from './WidgetSavedFiltersSelection';
import WidgetSavedFilterChips from './WidgetSavedFilterChips';
import WidgetSavedFiltersIcon from 'src/components/saved_filters/WidgetSavedFiltersIcon';
import Divider from '@mui/material/Divider';

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

  const isDashboardSavedFiltersFeatureEnabled = isFeatureEnable('DASHBOARD_SAVED_FILTERS');

  const [filters, helpers] = useFiltersState(dataSelection.filters);
  const [filtersDynamicFrom, helpersDynamicFrom] = useFiltersState(dataSelection.dynamicFrom);
  const [filtersDynamicTo, helpersDynamicTo] = useFiltersState(dataSelection.dynamicTo);
  const { host } = useWidgetConfigContext();
  const isSavedFiltersAccessible = isDashboardSavedFiltersFeatureEnabled && host.kind === 'workspace';

  const [useSavedFilter, setUseSavedFilter] = useState(!!dataSelection.filters_id);
  const [useSavedFilterDynamicFrom, setUseSavedFilterDynamicFrom] = useState(!!dataSelection.dynamicFrom_id);
  const [useSavedFilterDynamicTo, setUseSavedFilterDynamicTo] = useState(!!dataSelection.dynamicTo_id);

  useEffect(() => {
    setDataSelection({
      ...dataSelection,
      filters,
      dynamicTo: filtersDynamicTo,
      dynamicFrom: filtersDynamicFrom,
    });
  }, [filters, filtersDynamicFrom, filtersDynamicTo]);

  let availableEntityTypes;
  let searchContext;
  let savedFiltersScope: string;
  if (perspective === 'relationships') {
    searchContext = { entityTypes: ['stix-core-relationship', 'stix-sighting-relationship', 'contains', 'object-label'] };
    savedFiltersScope = 'stix-core-relationship';
  } else if (perspective === 'audits') {
    availableEntityTypes = ['History', 'Activity'];
    searchContext = { entityTypes: ['History'] };
    savedFiltersScope = 'History';
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
    savedFiltersScope = 'Stix-Core-Object';
  }

  let availableFilterKeys = useAvailableFilterKeysForEntityTypes(searchContext.entityTypes);
  if (perspective !== 'relationships') {
    availableFilterKeys = availableFilterKeys.concat('entity_type');
  } else {
    availableFilterKeys = availableFilterKeys.filter((key) => key !== 'entity_type'); // for relationships perspective widget, use the relationship_type filter
  }

  const entitiesFilters = useAvailableFilterKeysForEntityTypes(['Stix-Core-Object']);

  const bookmarkAvailableEntityTypes = ['Malware', 'Threat-Actor-Individual', 'Threat-Actor-Group', 'Intrusion-Set', 'Campaign'];

  const handleSavedFilterClear = () => {
    setDataSelection({
      ...dataSelection,
      filters_id: null,
    });
  };

  const handleSwitchToSavedFilter = () => {
    setUseSavedFilter(true);
    helpers?.handleClearAllFilters();
  };

  const handleSwitchToCustomFilters = () => {
    setUseSavedFilter(false);
    handleSavedFilterClear();
  };

  const handleSavedFilterSelect = (savedFilterId: string) => {
    setDataSelection({
      ...dataSelection,
      filters_id: savedFilterId,
      filters: undefined,
    });
  };

  const handleSwitchToSavedFilterDynamicFrom = () => {
    setUseSavedFilterDynamicFrom(true);
    helpersDynamicFrom?.handleClearAllFilters();
  };

  const handleSavedFilterClearDynamicFrom = () => {
    setDataSelection({
      ...dataSelection,
      dynamicFrom_id: null,
    });
  };

  const handleSwitchToCustomFiltersDynamicFrom = () => {
    setUseSavedFilterDynamicFrom(false);
    handleSavedFilterClearDynamicFrom();
  };

  const handleSavedFilterSelectDynamicFrom = (savedFilterId: string) => {
    setDataSelection({
      ...dataSelection,
      dynamicFrom_id: savedFilterId,
      dynamicFrom: undefined,
    });
  };

  const handleSwitchToSavedFilterDynamicTo = () => {
    setUseSavedFilterDynamicTo(true);
    helpersDynamicTo?.handleClearAllFilters();
  };

  const handleSavedFilterClearDynamicTo = () => {
    setDataSelection({
      ...dataSelection,
      dynamicTo_id: null,
    });
  };

  const handleSwitchToCustomFiltersDynamicTo = () => {
    setUseSavedFilterDynamicTo(false);
    handleSavedFilterClearDynamicTo();
  };

  const handleSavedFilterSelectDynamicTo = (savedFilterId: string) => {
    setDataSelection({
      ...dataSelection,
      dynamicTo_id: savedFilterId,
      dynamicTo: undefined,
    });
  };

  return (
    <>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', paddingTop: 2 }}>
        <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
          {useSavedFilter ? (
            <>
              <WidgetSavedFiltersSelection
                scope={savedFiltersScope}
                onSelect={handleSavedFilterSelect}
                onDeselect={handleSwitchToCustomFilters}
                onClear={handleSavedFilterClear}
                selectedFilterId={dataSelection.filters_id}
              />
            </>
          ) : (
            <>
              <Filters
                availableFilterKeys={type === 'bookmark' ? ['entity_type'] : availableFilterKeys}
                availableEntityTypes={availableEntityTypes}
                helpers={helpers}
                searchContext={type === 'bookmark' ? undefined : searchContext}
              />
              {isSavedFiltersAccessible && (
                <>
                  <Divider orientation="vertical" flexItem />
                  <WidgetSavedFiltersIcon onClick={handleSwitchToSavedFilter} />
                </>
              )}
            </>
          )}
        </Box>

        {perspective === 'relationships' && (
          <>
            <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
              {useSavedFilterDynamicFrom ? (
                <>
                  <WidgetSavedFiltersSelection
                    scope="Stix-Core-Object"
                    onSelect={handleSavedFilterSelectDynamicFrom}
                    onDeselect={handleSwitchToCustomFiltersDynamicFrom}
                    onClear={handleSavedFilterClearDynamicFrom}
                    selectedFilterId={dataSelection.dynamicFrom_id}
                  />
                </>
              ) : (
                <>
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
                  <Divider orientation="vertical" flexItem />
                  {isSavedFiltersAccessible && (
                    <WidgetSavedFiltersIcon onClick={handleSwitchToSavedFilterDynamicFrom} />
                  )}
                </>
              )}
            </Box>
            <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
              {useSavedFilterDynamicTo ? (
                <>
                  <WidgetSavedFiltersSelection
                    scope="Stix-Core-Object"
                    onSelect={handleSavedFilterSelectDynamicTo}
                    onDeselect={handleSwitchToCustomFiltersDynamicTo}
                    onClear={handleSavedFilterClearDynamicTo}
                    selectedFilterId={dataSelection.dynamicTo_id}
                  />
                </>
              ) : (
                <>
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
                  <Divider orientation="vertical" flexItem />
                  {isSavedFiltersAccessible && (
                    <WidgetSavedFiltersIcon onClick={handleSwitchToSavedFilterDynamicTo} />
                  )}
                </>
              )}
            </Box>
          </>
        )}
      </Box>

      <Box sx={{ paddingTop: 1 }}>
        {(dataSelection.dynamicFrom_id || isFilterGroupNotEmpty(filtersDynamicFrom))
          && (
            <div style={{ marginTop: 8, color: 'orange', marginBottom: 4 }}>
              {t_i18n('Pre-query to get data to be used as source entity of the relationship (limited to 5000)')}
            </div>
          )
        }
        {dataSelection.dynamicFrom_id ? (
          <WidgetSavedFilterChips
            filterId={dataSelection.dynamicFrom_id}
            entityTypes={['Stix-Core-Object']}
            chipColor="warning"
          />
        ) : (
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
        )}

        {(dataSelection.dynamicTo_id || isFilterGroupNotEmpty(filtersDynamicTo))
          && (
            <div style={{ marginTop: 8, color: theme.palette.success.main, marginBottom: 4 }}>
              {t_i18n('Pre-query to get data to be used as target entity of the relationship (limited to 5000)')}
            </div>
          )
        }
        {dataSelection.dynamicTo_id ? (
          <WidgetSavedFilterChips
            filterId={dataSelection.dynamicTo_id}
            entityTypes={['Stix-Core-Object']}
            chipColor="success"
          />
        ) : (
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
        )}

        {perspective === 'relationships'
          && (dataSelection.filters_id || isFilterGroupNotEmpty(filters))
          && (
            <div style={{ marginTop: 8, marginBottom: 4 }}>
              {t_i18n('Result: the relationships with source respecting the source pre-query, target respecting the target pre-query, and matching:')}
            </div>
          )
        }
        {dataSelection.filters_id ? (
          <WidgetSavedFilterChips
            filterId={dataSelection.filters_id}
            entityTypes={searchContext.entityTypes}
          />
        ) : (
          <FilterIconButton
            filters={filters}
            helpers={helpers}
            searchContext={searchContext}
            availableEntityTypes={type === 'bookmark' ? bookmarkAvailableEntityTypes : availableEntityTypes}
            entityTypes={searchContext.entityTypes}
            host={host}
          />
        )}
      </Box>
    </>
  );
};

export default WidgetFilters;
