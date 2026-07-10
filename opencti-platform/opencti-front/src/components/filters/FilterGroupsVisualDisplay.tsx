import React, { Fragment, FunctionComponent } from 'react';
import Box from '@mui/material/Box';
import { Stack } from '@mui/material';
import { useFormatter } from '../i18n';
import { FilterRepresentative } from './FiltersModel';
import type { Filter, FilterGroup } from '../../utils/filters/filtersHelpers-types';

// ─── Shared style constants ──────────────────────────────────────────

const modeBadgeSx = {
  textTransform: 'uppercase',
  fontWeight: 'bold',
  borderRadius: '24px',
  padding: '8px 16px',
  fontFamily: 'Consolas, monaco, monospace',
  backgroundColor: 'primary.dark',
} as const;

const operatorBadgeSx = {
  textTransform: 'uppercase',
  fontFamily: 'Consolas, monaco, monospace',
  backgroundColor: 'rgba(74, 117, 162, 0.8)',
  fontWeight: 'bold',
  display: 'inline-block',
  margin: '0 8px',
  padding: '8px',
} as const;

const innerValuesModeBadgeSx = {
  textTransform: 'uppercase',
  fontFamily: 'Consolas, monaco, monospace',
  fontWeight: 'bold',
  display: 'inline-block',
  padding: '8px',
} as const;

// ─── FilterValuesDisplay ─────────────────────────────────────────────

interface FilterValuesDisplayProps {
  filtersRepresentativesMap: Map<string, FilterRepresentative>;
  values: string[];
  mode?: string;
}

const FilterValuesDisplay: FunctionComponent<FilterValuesDisplayProps> = ({
  filtersRepresentativesMap,
  values,
  mode,
}) => {
  const { t_i18n } = useFormatter();
  return (
    <>
      {values.map((value, j) => (
        <Fragment key={value}>
          <span>
            {' '}
            {filtersRepresentativesMap.get(value)?.value ?? value}{' '}
          </span>
          {j + 1 < values.length && (
            <Box
              sx={innerValuesModeBadgeSx}
            >
              {t_i18n(mode ?? 'or')}
            </Box>
          )}
        </Fragment>
      ))}
    </>
  );
};

// ─── FilterGroupsDisplay ─────────────────────────────────────────────

interface FilterGroupsVisualDisplayProps {
  filtersRepresentativesMap: Map<string, FilterRepresentative>;
  filterGroups: FilterGroup[];
  filterMode: string;
}

const FilterGroupsVisualDisplay: FunctionComponent<FilterGroupsVisualDisplayProps> = ({
  filtersRepresentativesMap,
  filterGroups,
  filterMode,
}) => {
  const { t_i18n } = useFormatter();

  const renderFilterValues = (f: Filter) => {
    const { key, values, mode } = f;

    // case of filters with subfilters
    if (key === 'regardingOf' || key === 'dynamicRegardingOf') {
      return (
        <>
          {values
            .filter((v) => v.key === 'relationship_type')
            .map((value) => (
              <span key="relationship_type">
                <FilterValuesDisplay
                  filtersRepresentativesMap={filtersRepresentativesMap}
                  values={value.values}
                />
              </span>
            ))}
          {values.filter((v) => v.key === 'id' || v.key === 'dynamic').length > 0 && (
            <Box
              sx={{
                ...innerValuesModeBadgeSx,
                margin: '0 8px',
              }}
            >
              {t_i18n('WITH')}
            </Box>
          )}
          {values.filter((v) => v.key === 'id').map((value) => (
            <span key="regardingOf-id">
              <FilterValuesDisplay
                filtersRepresentativesMap={filtersRepresentativesMap}
                values={value.values}
              />
            </span>
          ))}
          {values.filter((v) => v.key === 'dynamic').map((value) => (
            <span key="regardingOf-dynamic">
              <FilterGroupsVisualDisplay
                filterGroups={value.values}
                filtersRepresentativesMap={filtersRepresentativesMap}
                filterMode="and"
              />
            </span>
          ))}
        </>
      );
    }

    // case of filters with filters in 'values'
    if (key === 'dynamicTo' || key === 'dynamicFrom') {
      return (
        <FilterGroupsVisualDisplay
          filterGroups={values}
          filtersRepresentativesMap={filtersRepresentativesMap}
          filterMode={mode ?? 'or'}
        />
      );
    }

    // classic filters
    return (
      <FilterValuesDisplay
        filtersRepresentativesMap={filtersRepresentativesMap}
        values={values}
        mode={mode ?? 'or'}
      />
    );
  };

  const renderFilters = (filters: Filter[], parentMode: string) => {
    return filters.map((f, i) => {
      const { key, operator, id } = f;
      return (
        <Box
          key={id ?? `${key}-${i}`}
          sx={{
            display: 'grid',
            gridTemplateColumns: 'auto 1fr',
            gap: '8px',
            alignItems: 'center',
          }}
        >
          {i !== 0 && (
            <Box sx={{ ...modeBadgeSx, display: 'inline-block' }}>
              {parentMode}
            </Box>
          )}
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              gap: '16px',
              borderRadius: '24px',
              padding: '0 16px',
              backgroundColor: 'rgba(255, 255, 255, 0.35)',
              width: 'fit-content',
            }}
          >
            <span>{t_i18n(key)}</span>
            <Box sx={operatorBadgeSx}>
              {operator}
            </Box>
            <Box sx={{ display: 'inline-block' }}>
              {renderFilterValues(f)}
            </Box>
          </Box>
        </Box>
      );
    });
  };

  return filterGroups.map((f, i) => (
    <Fragment key={`filter-group-${i}`}>
      {i !== 0 && (
        <Box
          sx={{
            ...modeBadgeSx,
            display: 'inline-block',
            height: 'fit-content',
          }}
        >
          {filterMode}
        </Box>
      )}
      <Box
        sx={{
          padding: '16px',
          backgroundColor: 'rgba(0, 0, 0, 0.25)',
          marginBottom: '16px',
        }}
      >
        <Stack sx={{ gap: '8px', paddingBottom: '8px' }}>
          {renderFilters(f.filters, f.mode)}
        </Stack>
        {f.filterGroups.length > 0 && (
          <Stack direction="row">
            <Box
              sx={{
                ...modeBadgeSx,
                marginRight: '8px',
                height: 'fit-content',
              }}
            >
              {f.mode}
            </Box>
            <FilterGroupsVisualDisplay
              filtersRepresentativesMap={filtersRepresentativesMap}
              filterGroups={f.filterGroups}
              filterMode={filterMode}
            />
          </Stack>
        )}
      </Box>
    </Fragment>
  ));
};

export default FilterGroupsVisualDisplay;
