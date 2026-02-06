import React, { useState } from 'react';
import { useFormatter } from '../../../../../components/i18n';
import Breadcrumbs from '../../../../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../../../../utils/hooks/useConnectedDocumentModifier';
import { Box } from '@mui/material';
import DashboardFilterBar, { AppliedFilter } from './components/DashboardFilterBar';
import DashboardMetrics from './components/DashboardMetrics';

const OrganizationManagerDashboard = () => {
  const { t_i18n } = useFormatter();

  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Organization Manager Dashboard'));

  const [searchValue, setSearchValue] = useState('');
  const [appliedFilters, setAppliedFilters] = useState<AppliedFilter[]>([]);

  const handleSearch = () => {
    // TODO: Implement search functionality
    console.log('Searching for:', searchValue);
  };

  const handlePersonalizationClick = () => {
    // TODO: Implement personalization dialog
    console.log('Personalization clicked');
  };

  const handleFiltersClick = () => {
    // TODO: Implement filters dialog
    console.log('Filters clicked');
  };

  return (
    <>
      <Breadcrumbs
        elements={[
          { label: t_i18n('Dashboards') },
          { label: t_i18n('Organization Manager Dashboard'), current: true },
        ]}
      />
      <Box
        sx={{
          direction: 'ltr',
          backgroundColor: 'background.default',
          minHeight: '100vh',
        }}
      >
        {/* Filter Bar */}
        <DashboardFilterBar
          searchValue={searchValue}
          onSearchChange={setSearchValue}
          onSearch={handleSearch}
          appliedFilters={appliedFilters}
          onAppliedFiltersChange={setAppliedFilters}
          onPersonalizationClick={handlePersonalizationClick}
          onFiltersClick={handleFiltersClick}
        />

        {/* Dashboard Content */}
        <DashboardMetrics />
      </Box>
    </>
  );
};

export default OrganizationManagerDashboard;
