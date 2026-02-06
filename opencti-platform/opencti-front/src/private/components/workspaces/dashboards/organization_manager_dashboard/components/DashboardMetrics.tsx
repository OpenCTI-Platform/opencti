import React from 'react';
import { Grid, Box } from '@mui/material';
import GaugeCard from './GaugeCard';
import ActiveCampaignAlertsChart from './ActiveCampaignAlertsChart';
import VulnerabilityExploitationCard from './VulnerabilityExploitationCard';
import ThreatHuntingQueue from './ThreatHuntingQueue';
import TTPNetworkSection from './TTPNetworkSection';
import AttackerProfilesAndVulnerabilitySection from './AttackerProfilesAndVulnerabilitySection';
import TTPExplorerSection from './TTPExplorerSection';

const DashboardMetrics: React.FC = () => {
  return (
    <Box sx={{ paddingTop: 3, paddingBottom: 3, paddingLeft: 0, paddingRight: 0 }}>
      {/* Gauge Metrics Section */}
      <Grid container spacing={3} sx={{ direction: 'ltr' }}>
        <Grid item xs={12} sm={6} md={3}>
          <GaugeCard
            title="Index Compliance Rate"
            description="Percentage of compliance of input data from reports with existing IOCs"
            value={87}
            maxValue={100}
            unit="%"
            colors={['#f44336', '#ff5722', '#ff9800', '#ffeb3b', '#4caf50']}
            labels={['Critical', 'Concerning', 'Stable']}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <GaugeCard
            title="Reduction Success Rate"
            description="Ratio of discovered threats that have been successfully neutralized"
            value={66}
            maxValue={100}
            unit="%"
            colors={['#f44336', '#ff5722', '#ff9800', '#ffeb3b', '#4caf50']}
            labels={['Critical', 'Concerning', 'Stable']}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <GaugeCard
            title="True Positive IOCs Rate"
            description="Ratio of confirmed incidents to all CTI team alerts based on IOCs present in the system"
            value={35}
            maxValue={100}
            unit="%"
            colors={['#f44336', '#ff5722', '#ff9800', '#ffeb3b', '#4caf50']}
            labels={['Critical', 'Concerning', 'Stable']}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <GaugeCard
            title="TTP Detection Coverage"
            description="Percentage coverage of MITRE ATT&CK matrix"
            value={56}
            maxValue={100}
            unit="%"
            colors={['#f44336', '#ff5722', '#ff9800', '#ffeb3b', '#4caf50']}
            labels={['Critical', 'Concerning', 'Stable']}
          />
        </Grid>
      </Grid>

      {/* Active Campaign Alerts & Vulnerability Exploitation Section */}
      <Grid container spacing={3} sx={{ direction: 'ltr', marginTop: 2 }}>
        <Grid item xs={12} md={6}>
          <VulnerabilityExploitationCard />
        </Grid>
        <Grid item xs={12} md={6}>
          <ActiveCampaignAlertsChart />
        </Grid>
      </Grid>

      {/* Threat Hunting Queue Section */}
      <ThreatHuntingQueue />

      {/* TTP Network Graph & Details Section */}
      <TTPNetworkSection />

      {/* Attacker Profiles & Vulnerability Prioritization Section */}
      <AttackerProfilesAndVulnerabilitySection />

      {/* TTP Explorer Section */}
      <TTPExplorerSection />
    </Box>
  );
};

export default DashboardMetrics;
