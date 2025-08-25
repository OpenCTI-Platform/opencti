import React, { useEffect, useMemo, useState } from 'react';
import { Autocomplete, Stack, TextField } from '@mui/material';
import InputAdornment from '@mui/material/InputAdornment';
import { FilterListOffOutlined, Search } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { useFormatter } from '../../../../components/i18n';

interface Contract {
  title: string;
  use_cases: string[];
  verified: boolean;
  container_type: string;
}

interface FilterState {
  search: string;
  type: string;
  useCase: string;
}

interface IngestionCatalogFiltersProps {
  contracts: Contract[];
  filters: FilterState;
  onFiltersChange: (filters: FilterState) => void;
}

const INPUT_WIDTH = 200; // same as defined in ListFilters
const DEBOUNCE_DELAY = 300;

const formatTypeLabel = (type: string): string => {
  return type.toLowerCase().replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase());
};

const IngestionCatalogFilters: React.FC<IngestionCatalogFiltersProps> = ({
  contracts,
  filters,
  onFiltersChange,
}) => {
  const { t_i18n } = useFormatter();
  const [searchInput, setSearchInput] = useState(filters.search);

  useEffect(() => {
    const handler = setTimeout(() => {
      if (searchInput !== filters.search) {
        onFiltersChange({ ...filters, search: searchInput });
      }
    }, DEBOUNCE_DELAY); // 300ms debounce

    return () => clearTimeout(handler);
  }, [searchInput]);

  const filterOptions = useMemo(() => {
    const types: string[] = [];
    const useCases: string[] = [];

    for (const contract of contracts) {
      if (contract.container_type && !types.includes(contract.container_type)) {
        types.push(contract.container_type);
      }

      if (contract.use_cases) {
        for (const useCase of contract.use_cases) {
          if (!useCases.includes(useCase)) {
            useCases.push(useCase);
          }
        }
      }
    }

    return {
      types: types.sort().map((type) => ({
        value: type,
        label: formatTypeLabel(type),
      })),
      useCases: useCases.sort().map((useCase) => ({
        value: useCase,
        label: useCase,
      })),
    };
  }, [contracts]);

  const handleFilterChange = (key: keyof FilterState, value: string) => {
    onFiltersChange({ ...filters, [key]: value });
  };

  const handleClearFilters = () => {
    setSearchInput('');
    onFiltersChange({ search: '', type: '', useCase: '' });
  };

  const hasActiveFilters = filters.search || filters.type || filters.useCase;

  return (
    <Stack flexDirection="row" gap={2} flex={1}>
      <TextField
        placeholder={`${t_i18n('Search these results')}...`}
        variant="outlined"
        size="small"
        value={searchInput}
        onChange={(e) => setSearchInput(e.target.value)}
        sx={{ width: INPUT_WIDTH }}
        slotProps={{
          input: {
            startAdornment: (
              <InputAdornment position="start">
                <Search fontSize="small" />
              </InputAdornment>
            ),
          },
        }}
      />

      <Autocomplete
        size="small"
        sx={{ width: INPUT_WIDTH }}
        options={filterOptions.types}
        value={filterOptions.types.find((o) => o.value === filters.type) || null}
        onChange={(event, option) => handleFilterChange('type', option?.value || '')}
        getOptionLabel={(option) => option.label}
        isOptionEqualToValue={(option, value) => option.value === value.value}
        renderInput={(params) => (
          <TextField {...params} label={t_i18n('Types')} placeholder={t_i18n('Types')} variant="outlined" />
        )}
        clearOnEscape
      />

      <Autocomplete
        size="small"
        sx={{ width: INPUT_WIDTH }}
        options={filterOptions.useCases}
        value={filterOptions.useCases.find((o) => o.value === filters.useCase) || null}
        onChange={(event, option) => handleFilterChange('useCase', option?.value || '')}
        getOptionLabel={(option) => option.label}
        isOptionEqualToValue={(o, v) => o.value === v.value}
        renderInput={(params) => (
          <TextField {...params} label="Use Case" placeholder="Select use case..." variant="outlined" />
        )}
        clearOnEscape
      />

      <Tooltip title={t_i18n('Clear filters')}>
        <IconButton
          color={hasActiveFilters ? 'primary' : 'default'}
          onClick={handleClearFilters}
          size="small"
          disabled={!hasActiveFilters}
        >
          <FilterListOffOutlined fontSize="small" />
        </IconButton>
      </Tooltip>
    </Stack>
  );
};

export default IngestionCatalogFilters;
export type { Contract, FilterState };
