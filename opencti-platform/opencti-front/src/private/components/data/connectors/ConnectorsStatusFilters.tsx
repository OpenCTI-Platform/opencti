import { Combobox, ComboboxClear, ComboboxContent, ComboboxControls, ComboboxField, ComboboxInput, ComboboxLabel, ComboboxTrigger } from '@filigran/design-system';
import React, { ChangeEvent, useState } from 'react';
import { Stack } from '@mui/material';
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
              <div style={{ width: INPUT_WIDTH, backgroundColor: theme.palette.background.paper }}>
                <Combobox<{ label: string; value: string }>
                  options={managedConnectorOptions}
                  value={managedConnectorOptions.find((o) => o.value === filters.slug) || null}
                  onValueChange={(option) => handleFilterChange('slug', (option as { value: string } | null)?.value || '')}
                  isOptionEqualToValue={(a, b) => a.value === b.value}
                  getOptionLabel={(option) => option.label}
                >
                  <ComboboxLabel>{t_i18n('Managed connector')}</ComboboxLabel>
                  <ComboboxField>
                    <ComboboxInput placeholder={t_i18n('Connector')} />
                    <ComboboxControls>
                      <ComboboxClear />
                      <ComboboxTrigger />
                    </ComboboxControls>
                  </ComboboxField>
                  <ComboboxContent listAriaLabel={t_i18n('Managed connector')} />
                </Combobox>
              </div>
            </Tooltip>

            <div style={{ width: INPUT_WIDTH, backgroundColor: theme.palette.background.paper }}>
              <Combobox<{ label: string; value: boolean }>
                options={managedOptions}
                value={managedOptions.find((o) => o.value === filters.isManaged) || null}
                onValueChange={(option) => handleBooleanFilterChange('isManaged', (option as { value: boolean } | null)?.value ?? null)}
                isOptionEqualToValue={(a, b) => a.value === b.value}
                getOptionLabel={(option) => option.label}
              >
                <ComboboxLabel>{t_i18n('Manager deployment')}</ComboboxLabel>
                <ComboboxField>
                  <ComboboxInput />
                  <ComboboxControls>
                    <ComboboxClear />
                    <ComboboxTrigger />
                  </ComboboxControls>
                </ComboboxField>
                <ComboboxContent listAriaLabel={t_i18n('Manager deployment')} />
              </Combobox>
            </div>

            <ClearFiltersIcon
              hasActiveFilters={hasActiveFilters}
              onClear={handleClearFilters}
            />
          </>
        )
      }
    </Stack>
  );
};

export default ConnectorsStatusFilters;
