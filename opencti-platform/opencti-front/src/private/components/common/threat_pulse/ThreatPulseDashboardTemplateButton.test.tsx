import React, { useState } from 'react';
import { describe, expect, it } from 'vitest';
import { act, fireEvent, screen } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import testRender from '../../../../utils/tests/test-render';
import ThreatPulseDashboardTemplateButton, { ThreatPulseDashboardTemplateProvider } from './ThreatPulseDashboardTemplateButton';

type RelayEnv = ReturnType<typeof testRender>['relayEnv'];

const resolveAccess = (relayEnv: RelayEnv, access: string) => {
  act(() => {
    relayEnv.mock.getAllOperations().forEach((operation) => {
      relayEnv.mock.resolve(operation, MockPayloadGenerator.generate(operation, {
        PulseStatus: () => ({ id: 'pulse-status', access }),
      }));
    });
  });
};

// A list header that mounts its buttons again on every render, like the creation buttons of the dashboards list.
const RemountingHeader = () => {
  const [renders, setRenders] = useState(0);
  return (
    <div>
      <button type="button" onClick={() => setRenders(renders + 1)}>render the list again</button>
      <ThreatPulseDashboardTemplateButton key={renders} />
    </div>
  );
};

describe('ThreatPulseDashboardTemplateButton', () => {
  it('should keep the template dialog open when the header holding the button mounts again', async () => {
    const { relayEnv } = testRender(
      <ThreatPulseDashboardTemplateProvider>
        <RemountingHeader />
      </ThreatPulseDashboardTemplateProvider>,
    );
    resolveAccess(relayEnv, 'preview');

    fireEvent.click(await screen.findByTestId('threat-pulse-dashboard-template'));
    expect(await screen.findByTestId('threat-pulse-template-card')).toBeDefined();
    fireEvent.click(screen.getByText('render the list again'));
    resolveAccess(relayEnv, 'preview');

    expect(screen.getByTestId('threat-pulse-template-card')).toBeDefined();
    expect(screen.getByTestId('threat-pulse-template-preview-note')).toBeDefined();
  });

  it('should offer nothing outside a template provider or when Threat Pulse is off', async () => {
    const { relayEnv } = testRender(
      <>
        <ThreatPulseDashboardTemplateButton />
        <ThreatPulseDashboardTemplateProvider>
          <span>dashboards</span>
        </ThreatPulseDashboardTemplateProvider>
      </>,
    );
    resolveAccess(relayEnv, 'off');

    expect(await screen.findByText('dashboards')).toBeDefined();
    expect(screen.queryByTestId('threat-pulse-dashboard-template')).toBeNull();
    expect(screen.queryByTestId('threat-pulse-template-card')).toBeNull();
  });
});
