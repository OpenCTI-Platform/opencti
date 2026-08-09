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
import WidgetSavedFiltersSelection, { widgetSavedFiltersSelectionQuery } from './WidgetSavedFiltersSelection';
import WidgetSavedFilterChips from './WidgetSavedFilterChips';
import WidgetSavedFiltersIcon from 'src/components/saved_filters/WidgetSavedFiltersIcon';
import Divider from '@mui/material/Divider';
import { WidgetSavedFilterScope } from 'src/components/saved_filters/SavedFilterSelection';
import { fetchQuery } from '../../../relay/environment';
import type { WidgetSavedFiltersSelectionQuery } from './__generated__/WidgetSavedFiltersSelectionQuery.graphql';

const isSavedFilterScopeCompatible = (filterScope: string | null | undefined, scope: WidgetSavedFilterScope) => {
  if (!filterScope) return false;
  if (scope === 'stix-core-relationship') {
    return filterScope === 'relationships';
  }
  if (scope === 'History') {
    return filterScope.includes('audit');
  }
  if (scope === 'Stix-Core-Object') {
    return !filterScope.includes('audit') && filterScope !== 'relationships';
  }
};

interface WidgetFiltersProps {
  perspective: WidgetPerspective | null;
  type: string;
  dataSelection: WidgetDataSelection;
  setDataSelection: (data: WidgetDataSelection) => void;
}

const WidgetFilters: FunctionComponent<WidgetFiltersProps> = ({ perspective, type, dataSelection, setDataSelection }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();

  const [filters, helpers] = useFiltersState(dataSelection.filters);
  const [filtersDynamicFrom, helpersDynamicFrom] = useFiltersState(dataSelection.dynamicFrom);
  const [filtersDynamicTo, helpersDynamicTo] = useFiltersState(dataSelection.dynamicTo);
  const { host } = useWidgetConfigContext();
  const isSavedFiltersAccessible = host.kind === 'workspace' || host.kind === 'custom-view';

  const [isSavedFiltersMode, setIsSavedFiltersMode] = useState(!!dataSelection.filters_id);
  const [isSavedDynamicFromMode, setIsSavedDynamicFromMode] = useState(!!dataSelection.dynamicFrom_id);
  const [isSavedDynamicToMode, setIsSavedDynamicToMode] = useState(!!dataSelection.dynamicTo_id);
  const [availableSavedFiltersScopes, setAvailableSavedFiltersScopes] = useState<string[]>([]);

  useEffect(() => {
    setDataSelection({
      ...dataSelection,
      filters: isSavedFiltersMode ? undefined : filters,
      dynamicTo: isSavedDynamicToMode ? undefined : filtersDynamicTo,
      dynamicFrom: isSavedDynamicFromMode ? undefined : filtersDynamicFrom,
    });
  }, [
    filters,
    filtersDynamicFrom,
    filtersDynamicTo,
    isSavedFiltersMode,
    isSavedDynamicFromMode,
    isSavedDynamicToMode,
  ]);

  let availableEntityTypes;
  let searchContext;
  let savedFiltersScope: WidgetSavedFilterScope;
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
      'DraftWorkspace',
    ];
    const isDraftWorkspaceOnly = isDraftWorkspaceFilterGroup(filters);
    searchContext = isDraftWorkspaceOnly
      ? { entityTypes: ['Stix-Core-Object', 'DraftWorkspace'] }
      : { entityTypes: ['Stix-Core-Object'] };
    savedFiltersScope = 'Stix-Core-Object';
  }

  useEffect(() => {
    if (!isSavedFiltersAccessible) {
      setAvailableSavedFiltersScopes([]);
      return;
    }

    let isMounted = true;
    fetchQuery<WidgetSavedFiltersSelectionQuery>(widgetSavedFiltersSelectionQuery, {})
      .toPromise()
      .then((result) => {
        if (!isMounted) return;
        const scopes = result?.savedFilters?.edges
          ?.map((edge) => edge?.node?.scope)
          .filter((scope): scope is string => Boolean(scope)) ?? [];
        setAvailableSavedFiltersScopes(scopes);
      })
      .catch(() => {
        if (isMounted) {
          setAvailableSavedFiltersScopes([]);
        }
      });

    return () => {
      isMounted = false;
    };
  }, [isSavedFiltersAccessible]);

  const hasAvailableSavedFilters = (contextScope: WidgetSavedFilterScope) => {
    return availableSavedFiltersScopes.some((scope) => isSavedFilterScopeCompatible(scope, contextScope));
  };

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
    setIsSavedFiltersMode(true);
  };

  const handleSwitchToCustomFilters = () => {
    setIsSavedFiltersMode(false);
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
    setIsSavedDynamicFromMode(true);
  };

  const handleSavedFilterClearDynamicFrom = () => {
    setDataSelection({
      ...dataSelection,
      dynamicFrom_id: null,
    });
  };

  const handleSwitchToCustomFiltersDynamicFrom = () => {
    setIsSavedDynamicFromMode(false);
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
    setIsSavedDynamicToMode(true);
  };

  const handleSavedFilterClearDynamicTo = () => {
    setDataSelection({
      ...dataSelection,
      dynamicTo_id: null,
    });
  };

  const handleSwitchToCustomFiltersDynamicTo = () => {
    setIsSavedDynamicToMode(false);
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
          {isSavedFiltersMode ? (
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
                  <WidgetSavedFiltersIcon
                    onClick={handleSwitchToSavedFilter}
                    disabled={!hasAvailableSavedFilters(savedFiltersScope)}
                  />
                </>
              )}
            </>
          )}
        </Box>

        {perspective === 'relationships' && (
          <>
            <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
              {isSavedDynamicFromMode ? (
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
                    <WidgetSavedFiltersIcon
                      onClick={handleSwitchToSavedFilterDynamicFrom}
                      disabled={!hasAvailableSavedFilters('Stix-Core-Object')}
                    />
                  )}
                </>
              )}
            </Box>
            <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
              {isSavedDynamicToMode ? (
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
                    <WidgetSavedFiltersIcon
                      onClick={handleSwitchToSavedFilterDynamicTo}
                      disabled={!hasAvailableSavedFilters('Stix-Core-Object')}
                    />
                  )}
                </>
              )}
            </Box>
          </>
        )}
      </Box>

      <Box sx={{ paddingTop: 1 }}>
        {((isSavedDynamicFromMode && dataSelection.dynamicFrom_id)
          || (!isSavedDynamicFromMode && isFilterGroupNotEmpty(filtersDynamicFrom)))
        && (
          <div style={{ marginTop: 8, color: 'orange', marginBottom: 4 }}>
            {t_i18n('Pre-query to get data to be used as source entity of the relationship (limited to 5000)')}
          </div>
        )
        }
        {isSavedDynamicFromMode ? (
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

        {((isSavedDynamicToMode && dataSelection.dynamicTo_id)
          || (!isSavedDynamicToMode && isFilterGroupNotEmpty(filtersDynamicTo)))
        && (
          <div style={{ marginTop: 8, color: theme.palette.success.main, marginBottom: 4 }}>
            {t_i18n('Pre-query to get data to be used as target entity of the relationship (limited to 5000)')}
          </div>
        )
        }
        {isSavedDynamicToMode ? (
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
        {isSavedFiltersMode ? (
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
