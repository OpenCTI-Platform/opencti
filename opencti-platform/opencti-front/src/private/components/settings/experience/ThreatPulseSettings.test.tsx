import React from 'react';
import { describe, expect, it } from 'vitest';
import { act, fireEvent, screen, within } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import ThreatPulseSettings from './ThreatPulseSettings';

type RelayEnv = ReturnType<typeof testRender>['relayEnv'];

const administrator = createMockUserContext({ me: { id: 'admin', name: 'admin', capabilities: [{ name: 'BYPASS' }] } });
const analyst = createMockUserContext({ me: { id: 'analyst', name: 'analyst', capabilities: [{ name: 'KNOWLEDGE' }] } });

const SETTINGS = {
  id: 'pulse-settings',
  readable: false,
  hub_registered: true,
  consent_version: '2026-10-1',
  consent_accepted_version: null,
  consent_date: null,
  consent_user_name: null,
  scopes: ['Indicator', 'Malware'],
  available_scopes: ['Indicator', 'Malware'],
  excluded_markings: [],
  forced_excluded_markings: [],
  sector_bucket: null,
  region_bucket: null,
  suggested_sector_bucket: 'finance',
  suggested_region_bucket: 'europe',
  contribution: { last_push_at: null, last_refresh_at: null, last_error: null, total_records: 0, days: [], by_type: [] },
  preview: { last_refresh_at: '2026-10-03T06:00:00.000Z', digest_day: '2026-10-03', digest_items: 5000, matched_entities: 12 },
  network: {
    reachable: true,
    k_threshold: 5,
    retention_months: 13,
    contributors_bucket: '25-49',
    read_access: false,
    last_contribution_day: null,
    contribution_status: 'none',
    read_access_until: null,
    contribution_grace_days: 14,
  },
};

const IN_PREVIEW = { mode: 'preview', access: 'preview', enabled: false };
const LAPSED = {
  mode: 'contribute_and_read',
  access: 'preview',
  enabled: true,
  network: { ...SETTINGS.network, contribution_status: 'lapsed', last_contribution_day: '2026-09-10' },
};

const renderSettings = (settings: Record<string, unknown>, userContext = administrator): RelayEnv => {
  const { relayEnv } = testRender(<ThreatPulseSettings />, { userContext });
  act(() => {
    relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
      PulseSettings: () => ({ ...SETTINGS, ...settings }),
      MarkingDefinitionConnection: () => ({ edges: [] }),
    }));
  });
  return relayEnv;
};

const lastConfigureInput = (relayEnv: RelayEnv) => {
  const operation = relayEnv.mock.getMostRecentOperation();
  expect(operation.request.node.operation.name).toBe('ThreatPulseSettingsConfigureMutation');
  return operation.request.variables.input;
};

describe('ThreatPulseSettings', () => {
  it('should show what the preview matched and send nothing', async () => {
    renderSettings(IN_PREVIEW);
    expect(await screen.findByTestId('threat-pulse-preview-status')).toBeDefined();
    expect(screen.getByTestId('threat-pulse-preview-matched').textContent).toBe('12');
    expect(screen.getByText('Nothing: the digest is downloaded and matched on this platform')).toBeDefined();
    expect(screen.getByTestId('threat-pulse-enable-button')).toBeDefined();
    expect(screen.getByTestId('threat-pulse-disable-button')).toBeDefined();
    expect(screen.queryByTestId('threat-pulse-stop-button')).toBeNull();
  });

  it('should require the consent before contributing', async () => {
    const relayEnv = renderSettings(IN_PREVIEW);
    fireEvent.click(await screen.findByTestId('threat-pulse-enable-button'));
    const dialog = await screen.findByTestId('threat-pulse-consent-dialog');
    const accept = screen.getByTestId('threat-pulse-consent-accept');
    expect(accept.hasAttribute('disabled')).toBe(true);
    fireEvent.click(within(dialog).getByRole('checkbox'));
    expect(accept.hasAttribute('disabled')).toBe(false);
    fireEvent.click(accept);
    expect(lastConfigureInput(relayEnv)).toEqual({ mode: 'contribute_and_read', sector_bucket: 'finance', region_bucket: 'europe', consent_version: '2026-10-1' });
  });

  it('should turn the preview off', async () => {
    const relayEnv = renderSettings(IN_PREVIEW);
    fireEvent.click(await screen.findByTestId('threat-pulse-disable-button'));
    expect(lastConfigureInput(relayEnv)).toMatchObject({ mode: 'off' });
  });

  it('should turn the preview back on once turned off', async () => {
    const relayEnv = renderSettings({ mode: 'off', access: 'off', enabled: false });
    expect(screen.queryByTestId('threat-pulse-preview-status')).toBeNull();
    fireEvent.click(await screen.findByTestId('threat-pulse-preview-button'));
    expect(lastConfigureInput(relayEnv)).toMatchObject({ mode: 'preview' });
  });

  it('should say when XTM Hub stopped the full experience after the grace period, and let the contribution stop', async () => {
    const relayEnv = renderSettings(LAPSED);
    expect(await screen.findByTestId('threat-pulse-lapsed')).toBeDefined();
    expect(screen.getByText('Contribution lapsed - preview')).toBeDefined();
    expect(screen.getByTestId('threat-pulse-contribution-status').textContent).toContain('Lapsed');
    fireEvent.click(screen.getByTestId('threat-pulse-stop-button'));
    expect(lastConfigureInput(relayEnv)).toMatchObject({ mode: 'preview' });
  });

  it('should show the state without any action to a user who cannot manage XTM Hub', async () => {
    renderSettings(IN_PREVIEW, analyst);
    expect(await screen.findByTestId('threat-pulse-preview-status')).toBeDefined();
    expect(screen.queryByTestId('threat-pulse-enable-button')).toBeNull();
    expect(screen.queryByTestId('threat-pulse-disable-button')).toBeNull();
  });
});
