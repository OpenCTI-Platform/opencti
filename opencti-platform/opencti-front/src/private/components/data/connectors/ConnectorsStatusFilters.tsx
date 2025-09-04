import React, { ChangeEvent, useMemo, useState } from 'react';
import { Autocomplete, Stack, TextField } from '@mui/material';
import { FilterListOffOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { ConnectorsStatus_data$data } from '@components/data/connectors/__generated__/ConnectorsStatus_data.graphql';
import { useFormatter } from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';

type Connector = NonNullable<ConnectorsStatus_data$data['connectors']>[number];

export interface ConnectorsStatusFilterState {
  search: string;
  managerContractImage: string;
}

interface ConnectorsStatusFiltersProps {
  connectors: readonly Connector[];
  filters: ConnectorsStatusFilterState;
  onFiltersChange: (filters: ConnectorsStatusFilterState) => void;
}

const INPUT_WIDTH = 200; // same as defined in ListFilters

const ConnectorsStatusFilters: React.FC<ConnectorsStatusFiltersProps> = ({
  connectors,
  filters,
  onFiltersChange,
}) => {
  const { t_i18n } = useFormatter();
  const [searchInput, setSearchInput] = useState(filters.search);

  const filterOptions = useMemo(() => {
    const validImages = connectors
      .filter((connector) => connector.manager_contract_image != null && connector.manager_contract_image !== '')
      .map((connector) => connector.manager_contract_image);

    const uniqueImages = validImages.filter(
      (image, index) => validImages.indexOf(image) === index,
    );

    const managerContractImageOptions = uniqueImages.map((image) => ({
      label: image,
      value: image,
    }));

    return {
      managerContractImage: managerContractImageOptions,
    };
  }, [connectors]);

  const handleFilterChange = (key: keyof ConnectorsStatusFilterState, value: string) => {
    onFiltersChange({ ...filters, [key]: value });
  };

  const handleClearFilters = () => {
    setSearchInput('');
    onFiltersChange({ search: '', managerContractImage: '' });
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

  const hasActiveFilters = filters.search || filters.managerContractImage;

  return (
    <Stack flexDirection="row" gap={2} flex={1} alignItems="center">
      <SearchInput
        value={searchInput}
        onSubmit={handleSearchInputSubmit}
        onChange={handleSearchInputChange}
      />

      <Autocomplete
        size="small"
        sx={{ width: INPUT_WIDTH }}
        options={filterOptions.managerContractImage}
        value={filterOptions.managerContractImage.find((o) => o.value === filters.managerContractImage) || null}
        onChange={(event, option) => handleFilterChange('managerContractImage', option?.value || '')}
        isOptionEqualToValue={(option, value) => option.value === value.value}
        renderInput={(params) => (
          <TextField {...params} label={t_i18n('Types')} placeholder={t_i18n('Types')} variant="outlined" />
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

export default ConnectorsStatusFilters;
