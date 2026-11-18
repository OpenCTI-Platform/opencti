import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import XtmHubSaasMetrics from './XtmHubSaasMetrics';

const METRICS_URL = 'https://hub.filigran.io/redirect/opencti-registration?platform_id=platform-id';

describe('XtmHubSaasMetrics', () => {
  it('renders the SaaS metrics pitch', () => {
    testRender(<XtmHubSaasMetrics metricsUrl={METRICS_URL} />);

    expect(screen.getByText('Your OpenCTI, by the numbers')).toBeInTheDocument();
    expect(screen.getByText('Your plan')).toBeInTheDocument();
    expect(screen.getByText('Contract countdown')).toBeInTheDocument();
    expect(screen.getByText('Storage & uptime')).toBeInTheDocument();
  });

  it('links to the metrics on the hub in a new tab', () => {
    testRender(<XtmHubSaasMetrics metricsUrl={METRICS_URL} />);

    const metricsLink = screen.getByRole('link', { name: 'See my OpenCTI metrics' });
    expect(metricsLink).toHaveAttribute('href', METRICS_URL);
    expect(metricsLink).toHaveAttribute('target', '_blank');
  });
});
