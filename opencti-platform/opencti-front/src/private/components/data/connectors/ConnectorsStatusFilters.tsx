import React, { ChangeEvent, useState } from 'react';
import { Autocomplete, Stack, TextField } from '@mui/material';
import { FilterListOffOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';

export interface ConnectorsStatusFilterState {
  search: string;
  managerContractImage: string;
  isManaged: boolean | null
}

interface ConnectorsStatusFiltersProps {
  typeOptions: { label: string; value: string }[];
  filters: ConnectorsStatusFilterState;
  onFiltersChange: (filters: ConnectorsStatusFilterState) => void;
}

const INPUT_WIDTH = 200; // same as defined in ListFilters

const ConnectorsStatusFilters: React.FC<ConnectorsStatusFiltersProps> = ({
  typeOptions,
  filters,
  onFiltersChange,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const [searchInput, setSearchInput] = useState(filters.search);

  const isEnterpriseEdition = useEnterpriseEdition();

  const handleFilterChange = (key: keyof ConnectorsStatusFilterState, value: string) => {
    onFiltersChange({ ...filters, [key]: value });
  };

  const handleBooleanFilterChange = (key: keyof ConnectorsStatusFilterState, value: boolean | null) => {
    onFiltersChange({ ...filters, [key]: value });
  };

  const handleClearFilters = () => {
    setSearchInput('');
    onFiltersChange({ search: '', managerContractImage: '', isManaged: null });
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

  const hasActiveFilters = filters.search || filters.managerContractImage || filters.isManaged !== null;

  const managedOptions = [
    { label: 'True', value: true },
    { label: 'False', value: false },
  ];

  return (
    <Stack flexDirection="row" gap={2} flex={1} alignItems="center">
      <SearchInput
        value={searchInput}
        onSubmit={handleSearchInputSubmit}
        onChange={handleSearchInputChange}
      />

      {
        isEnterpriseEdition && (
          <>
            <Tooltip title={t_i18n('Apply filter to managed deployments only')} placement={'top'} >
              <Autocomplete
                size="small"
                sx={{ width: INPUT_WIDTH, backgroundColor: theme.palette.background.paper }}
                options={typeOptions}
                value={typeOptions.find((o) => o.value === filters.managerContractImage) || null}
                onChange={(event, option) => handleFilterChange('managerContractImage', option?.value || '')}
                isOptionEqualToValue={(option, value) => option.value === value.value}
                renderInput={(params) => (
                  <TextField {...params} label={t_i18n('Connector')} placeholder={t_i18n('Connector')} variant="outlined" />
                )}
                clearOnEscape
              />
            </Tooltip>

            <Autocomplete
              size="small"
              sx={{ width: INPUT_WIDTH, backgroundColor: theme.palette.background.paper }}
              options={managedOptions}
              value={managedOptions.find((o) => o.value === filters.isManaged) || null} // This will show empty when isManaged is null
              onChange={(event, option) => handleBooleanFilterChange('isManaged', option?.value ?? null)}
              isOptionEqualToValue={(option, value) => option.value === value.value}
              renderInput={(params) => (
                <TextField {...params} label={t_i18n('Manager deployment')} variant="outlined" />
              )}
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
          </>
        )
      }
    </Stack>
  );
};

export default ConnectorsStatusFilters;
