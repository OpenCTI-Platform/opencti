import React, { useState } from 'react';
import { useFormatter } from '../../../../../components/i18n';
import Breadcrumbs from '../../../../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../../../../utils/hooks/useConnectedDocumentModifier';
import { Box } from '@mui/material';
import DashboardFilterBar, { AppliedFilter } from '../organization_manager_dashboard/components/DashboardFilterBar';
import OperationalMetricsSection from './components/OperationalMetricsSection';
import ExploitAndAlertSection from './components/ExploitAndAlertSection';
import ThreatHuntingQueueBoard from './components/ThreatHuntingQueueBoard';
import TTPNetworkGraphSection from './components/TTPNetworkGraphSection';
import VulnAndProfilesSection from './components/VulnAndProfilesSection';
import TTPExplorerSection from './components/TTPExplorerSection';

const OperationalManagersDashboard = () => {
  const { t_i18n } = useFormatter();

  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Operational Managers Dashboard'));

  const [searchValue, setSearchValue] = useState('');
  const [appliedFilters, setAppliedFilters] = useState<AppliedFilter[]>([]);

  const handleSearch = () => {
    console.log('Searching for:', searchValue);
  };

  const handlePersonalizationClick = () => {
    console.log('Personalization clicked');
  };

  const handleFiltersClick = () => {
    console.log('Filters clicked');
  };

  return (
    <>
      <Breadcrumbs
        elements={[
          { label: t_i18n('Dashboards') },
          { label: t_i18n('Operational Managers Dashboard'), current: true },
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
        <Box sx={{ paddingTop: 3, paddingBottom: 3 }}>
          {/* Operational Metrics Section */}
          <OperationalMetricsSection />

          {/* Vulnerability Exploitation Window & Active Campaign Alerts */}
          <ExploitAndAlertSection />

          {/* Threat Hunting Queue (Kanban Board) */}
          <ThreatHuntingQueueBoard />

          {/* TTP Network Graph */}
          <TTPNetworkGraphSection />

          {/* Vulnerability Prioritization & Attacker Profiles */}
          <VulnAndProfilesSection />

          {/* TTP Explorer */}
          <TTPExplorerSection />
        </Box>
      </Box>
    </>
  );
};

export default OperationalManagersDashboard;
