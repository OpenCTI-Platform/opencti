import React, { Suspense } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import Grid from '@mui/material/Grid';
import { ThreatPulseHomeWidgetQuery } from './__generated__/ThreatPulseHomeWidgetQuery.graphql';
import ThreatPulseTrending from './ThreatPulseTrending';

export const threatPulseHomeWidgetQuery = graphql`
  query ThreatPulseHomeWidgetQuery {
    pulseStatus {
      id
      readable
    }
  }
`;

const ThreatPulseHomeWidgetComponent = () => {
  const { pulseStatus } = useLazyLoadQuery<ThreatPulseHomeWidgetQuery>(threatPulseHomeWidgetQuery, {}, { fetchPolicy: 'store-and-network' });
  if (!pulseStatus.readable) {
    return null;
  }
  return (
    <Grid item xs={12}>
      <ThreatPulseTrending />
    </Grid>
  );
};

// "Trending in your sector" row of the default home dashboard, only on platforms reading Threat Pulse.
const ThreatPulseHomeWidget = () => (
  <Suspense fallback={null}>
    <ThreatPulseHomeWidgetComponent />
  </Suspense>
);

export default ThreatPulseHomeWidget;
