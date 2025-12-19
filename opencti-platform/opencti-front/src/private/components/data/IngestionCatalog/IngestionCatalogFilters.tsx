import React, { ChangeEvent, useMemo, useState } from 'react';
import { Autocomplete, Stack, TextField } from '@mui/material';
import { FilterListOffOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@common/button/IconButton';
import { getConnectorMetadata, IngestionConnectorType } from '@components/data/IngestionCatalog/utils/ingestionConnectorTypeMetadata';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';

interface Contract {
  title: string;
  use_cases: string[];
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

const IngestionCatalogFilters: React.FC<IngestionCatalogFiltersProps> = ({
  contracts,
  filters,
  onFiltersChange,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const [searchInput, setSearchInput] = useState(filters.search);

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
        label: type,
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

  const handleSearchInputSubmit = (value: string) => {
    setSearchInput(value);
    onFiltersChange({ ...filters, search: value });
  };

  const handleSearchInputChange = (event: ChangeEvent<HTMLInputElement>) => {
    const { value } = event.currentTarget;
    setSearchInput(value);

    if (!value) {
      onFiltersChange({ ...filters, search: '' });
    }
  };

  const hasActiveFilters = filters.search || filters.type || filters.useCase;

  return (
    <Stack flexDirection="row" gap={2} flex={1} alignItems="center">
      <SearchInput
        value={searchInput}
        onSubmit={handleSearchInputSubmit}
        onChange={handleSearchInputChange}
      />

      <Autocomplete
        size="small"
        sx={{ width: INPUT_WIDTH, backgroundColor: theme.palette.background.paper }}
        options={filterOptions.types}
        value={filterOptions.types.find((o) => o.value === filters.type) || null}
        onChange={(event, option) => handleFilterChange('type', option?.value || '')}
        getOptionLabel={(option) => {
          const metadata = getConnectorMetadata(option.label as IngestionConnectorType, t_i18n);
          // metadata.label is translated from getConnectorMetadata
          return metadata ? metadata.label : t_i18n(option.label);
        }}
        isOptionEqualToValue={(option, value) => option.value === value.value}
        renderInput={(params) => (
          <TextField {...params} label={t_i18n('Type')} placeholder={t_i18n('Type')} variant="outlined" />
        )}
        clearOnEscape
      />

      <Autocomplete
        size="small"
        sx={{ width: INPUT_WIDTH, backgroundColor: theme.palette.background.paper }}
        options={filterOptions.useCases}
        value={filterOptions.useCases.find((o) => o.value === filters.useCase) || null}
        onChange={(event, option) => handleFilterChange('useCase', option?.value || '')}
        getOptionLabel={(option) => option.label} // no translation on purpose
        isOptionEqualToValue={(option, value) => option.value === value.value}
        renderInput={(params) => (
          <TextField {...params} label={t_i18n('Use case')} variant="outlined" />
        )}
        clearOnEscape
      />

      <Tooltip title={t_i18n('Clear filters')}>
        <span>
          <IconButton
            color={hasActiveFilters ? 'primary' : 'default'}
            onClick={handleClearFilters}
            size="small"
            disabled={!hasActiveFilters}
          >
            <FilterListOffOutlined fontSize="small" />
          </IconButton>
        </span>
      </Tooltip>
    </Stack>
  );
};

export default IngestionCatalogFilters;
export type { Contract, FilterState };
