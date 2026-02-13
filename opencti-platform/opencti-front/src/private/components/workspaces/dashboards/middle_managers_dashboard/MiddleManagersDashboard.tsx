import React, { useState } from 'react';
import { useFormatter } from '../../../../../components/i18n';
import Breadcrumbs from '../../../../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../../../../utils/hooks/useConnectedDocumentModifier';
import { Box } from '@mui/material';
import DashboardFilterBar, { AppliedFilter } from '../organization_manager_dashboard/components/DashboardFilterBar';
import CampaignsAndPerformanceSection from './components/CampaignsAndPerformanceSection';
import HacktivistActivitySection from './components/HacktivistActivitySection';
import VulnerabilityAndTeamSection from './components/VulnerabilityAndTeamSection';
import ResponseAndEffectivenessSection from './components/ResponseAndEffectivenessSection';
import TTPHeatmapSection from './components/TTPHeatmapSection';
import IncidentResponseTable from './components/IncidentResponseTable';
import CampaignsAndResourceSection from './components/CampaignsAndResourceSection';
import VulnerabilityPrioritizationTable from './components/VulnerabilityPrioritizationTable';

const MiddleManagersDashboard = () => {
  const { t_i18n } = useFormatter();

  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Middle Managers Dashboard'));

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
          { label: t_i18n('Middle Managers Dashboard'), current: true },
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
          {/* Campaigns & Performance Section */}
          <CampaignsAndPerformanceSection />

          {/* Hacktivist Activity Count Section */}
          <HacktivistActivitySection />

          {/* Vulnerability Prioritization & Technical Team Performance Section */}
          <VulnerabilityAndTeamSection />

          {/* Incident Response Time & Geographical Effectiveness Section */}
          <ResponseAndEffectivenessSection />

          {/* TTP Heatmap Section */}
          <TTPHeatmapSection />

          {/* Incident Response Table (Kanban Board) */}
          <IncidentResponseTable />

          {/* Current Campaigns & Resource Allocation Section */}
          <CampaignsAndResourceSection />

          {/* Vulnerability Prioritization Table */}
          <VulnerabilityPrioritizationTable />
        </Box>
      </Box>
    </>
  );
};

export default MiddleManagersDashboard;
