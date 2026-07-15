import React, { ChangeEvent, useState } from 'react';
import { Autocomplete, Stack, TextField } from '@mui/material';
import Tooltip from '@mui/material/Tooltip';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import ClearFiltersIcon from 'src/components/filters/ClearFiltersIcon';

export interface ConnectorsStatusFilterState {
  search: string;
  slug: string;
  isManaged: boolean | null;
}

interface ConnectorsStatusFiltersProps {
  managedConnectorOptions: { label: string; value: string }[];
  filters: ConnectorsStatusFilterState;
  onFiltersChange: (filters: ConnectorsStatusFilterState) => void;
  showManagedFilters: boolean;
}

const INPUT_WIDTH = 200; // same as defined in ListFilters

const ConnectorsStatusFilters: React.FC<ConnectorsStatusFiltersProps> = ({
  managedConnectorOptions,
  filters,
  onFiltersChange,
  showManagedFilters = false,
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
    onFiltersChange({ search: '', slug: '', isManaged: null });
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

  const hasActiveFilters = !!filters.search || !!filters.slug || filters.isManaged !== null;

  const managedOptions = [
    { label: 'True', value: true },
    { label: 'False', value: false },
  ];

  return (
    <Stack flexDirection="row" gap={2} alignItems="center">
      <SearchInput
        value={searchInput}
        onSubmit={handleSearchInputSubmit}
        onChange={handleSearchInputChange}
      />

      {
        isEnterpriseEdition && showManagedFilters && (
          <>
            <Tooltip title={t_i18n('Apply filter to managed deployments only')} placement="top">
              <Autocomplete
                size="small"
                sx={{ width: INPUT_WIDTH, backgroundColor: theme.palette.background.paper }}
                options={managedConnectorOptions}
                value={managedConnectorOptions.find((o) => o.value === filters.slug) || null}
                onChange={(event, option) => handleFilterChange('slug', option?.value || '')}
                isOptionEqualToValue={(option, value) => option.value === value.value}
                renderInput={(params) => (
                  <TextField {...params} label={t_i18n('Managed connector')} placeholder={t_i18n('Connector')} variant="outlined" />
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

            <ClearFiltersIcon
              hasActiveFilters={hasActiveFilters}
              handleClearFilters={handleClearFilters}
            />
          </>
        )
      }
    </Stack>
  );
};

export default ConnectorsStatusFilters;
