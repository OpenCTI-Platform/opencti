import React from 'react';
import { Box } from '@mui/material';
import NationalMetricsSection from './NationalMetricsSection';
import CyberRatesSection from './CyberRatesSection';
import ThreatAnalysisSection from './ThreatAnalysisSection';
import StrategicThreatSection from './StrategicThreatSection';
import GeoThreatSection from './GeoThreatSection';

const DashboardMetrics: React.FC = () => {
  return (
    <Box sx={{ paddingTop: 3, paddingBottom: 3, paddingLeft: 0, paddingRight: 0 }}>
      {/* National Metrics Section (Risk Score, MTTD, MTCR) */}
      <NationalMetricsSection />

      {/* Cyber Compliance & Gap Rates Section */}
      <CyberRatesSection />

      {/* Threat Analysis Section (Cross-Sector Impact & Threat Trend Velocity) */}
      <ThreatAnalysisSection />

      {/* Strategic Threat Section (Top Attackers, High Confidence Campaigns, Resource Allocation) */}
      <StrategicThreatSection />

      {/* Geo Threat Section (National Threat Heatmap & Targeted Industries) */}
      <GeoThreatSection />
    </Box>
  );
};

export default DashboardMetrics;
