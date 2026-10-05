import React from 'react';
import { describe, expect, it } from 'vitest';
import { act, cleanup, fireEvent, screen, within } from '@testing-library/react';
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
    // The privacy choices are made in the consent step and travel with it
    expect(within(dialog).getByTestId('threat-pulse-consent-privacy')).toBeDefined();
    fireEvent.click(accept);
    expect(lastConfigureInput(relayEnv)).toEqual({
      mode: 'contribute_and_read',
      sector_bucket: 'finance',
      region_bucket: 'europe',
      scopes: ['Indicator', 'Malware'],
      excluded_markings: [],
      consent_version: '2026-10-1',
    });
  });

  it('should list what is shared, what never leaves and what contributing unlocks in the consent', async () => {
    renderSettings(IN_PREVIEW);
    fireEvent.click(await screen.findByTestId('threat-pulse-enable-button'));
    const dialog = await screen.findByTestId('threat-pulse-consent-dialog');
    expect(within(dialog).getByTestId('threat-pulse-consent-shared').textContent).toContain('What is shared every hour');
    expect(within(dialog).getByTestId('threat-pulse-consent-never').textContent).toContain('TLP:RED, TLP:AMBER+STRICT or PAP:RED');
    expect(within(dialog).getByTestId('threat-pulse-consent-unlocks').textContent).toContain('What you unlock');
    expect(within(dialog).getByText(/only once 5 platforms or more reported the same object/)).toBeDefined();
    expect(within(dialog).queryByText(/bucket/i)).toBeNull();
  });

  it('should explain each setting under its field, in the consent and in the settings of a contributing platform', async () => {
    const helps = [
      /^Shared with each contribution as a coarse category, never your organization's name\. Sets the sector/,
      /^Shared with each contribution as a coarse category, never your organization's name\. The preview reads/,
      /^Only objects of these types are hashed and counted in the contribution/,
      /^Objects with one of these markings are never contributed or looked up/,
    ];
    renderSettings(IN_PREVIEW);
    fireEvent.click(await screen.findByTestId('threat-pulse-enable-button'));
    const dialog = await screen.findByTestId('threat-pulse-consent-dialog');
    helps.forEach((help) => expect(within(dialog).getAllByText(help)).toHaveLength(1));
    cleanup();
    renderSettings({ mode: 'contribute_and_read', access: 'full', enabled: true });
    const configuration = await screen.findByTestId('threat-pulse-configuration');
    helps.forEach((help) => expect(within(configuration).getAllByText(help)).toHaveLength(1));
  });

  it('should state every value of a contributing platform in words, never a raw value or a dash', async () => {
    renderSettings({
      mode: 'contribute_and_read',
      access: 'full',
      enabled: true,
      contribution: { ...SETTINGS.contribution, last_error: 'hub_unreachable' },
      network: { ...SETTINGS.network, contribution_status: 'active', read_access: true },
    });
    expect(await screen.findByTestId('threat-pulse-configuration')).toBeDefined();
    expect(screen.getByText('Contributing')).toBeDefined();
    expect(screen.getByText('25 to 49 platforms')).toBeDefined();
    expect(screen.getByText('5 platforms - contributions kept 13 months')).toBeDefined();
    expect(screen.getByText('Not given yet')).toBeDefined();
    expect(screen.getAllByText('None yet')).toHaveLength(2);
    expect(screen.getByTestId('threat-pulse-last-error').textContent).toBe('XTM Hub could not be reached: the pending records are sent with the next hourly run.');
    expect(screen.queryByText('-')).toBeNull();
    expect(screen.queryByText('hub_unreachable')).toBeNull();
  });

  it.each([
    ['cleanup_failed', 'The removal of community data that is no longer current failed: the next hourly run tries again.'],
    ['network_refresh_failed', 'The refresh of the community data of your objects failed: the next hourly run tries again.'],
    ['trending_notifications_failed', 'The notifications of objects trending in your sector failed: the next hourly run tries again.'],
    ['preview_refresh_failed', 'The preview refresh failed: the next hourly run tries again.'],
    ['contribution_failed', 'The last contribution failed on this platform: the next hourly run tries again with the pending records.'],
  ])('should name the step of the hourly cycle that failed (%s)', async (lastError, message) => {
    renderSettings({
      mode: 'contribute_and_read',
      access: 'full',
      enabled: true,
      contribution: { ...SETTINGS.contribution, last_error: lastError },
      network: { ...SETTINGS.network, contribution_status: 'active', read_access: true },
    });
    expect((await screen.findByTestId('threat-pulse-last-error')).textContent).toBe(message);
  });

  it('should keep the consent open when the contribution is not enabled', async () => {
    const relayEnv = renderSettings(IN_PREVIEW);
    fireEvent.click(await screen.findByTestId('threat-pulse-enable-button'));
    const dialog = await screen.findByTestId('threat-pulse-consent-dialog');
    fireEvent.click(within(dialog).getByRole('checkbox'));
    fireEvent.click(screen.getByTestId('threat-pulse-consent-accept'));
    act(() => {
      relayEnv.mock.resolveMostRecentOperation({ data: { pulseConfigure: null }, errors: [{ message: 'XTM Hub is unreachable' }] } as never);
    });
    expect(screen.getByTestId('threat-pulse-consent-dialog')).toBeDefined();
  });

  it('should not report a purge that XTM Hub rejected', async () => {
    const relayEnv = renderSettings({ mode: 'contribute_and_read', access: 'full', enabled: true });
    fireEvent.click(await screen.findByTestId('threat-pulse-purge-button'));
    fireEvent.click(await screen.findByTestId('threat-pulse-purge-confirm'));
    const operation = relayEnv.mock.getMostRecentOperation();
    expect(operation.request.node.operation.name).toBe('ThreatPulseSettingsPurgeMutation');
    act(() => {
      relayEnv.mock.resolveMostRecentOperation({ data: { pulsePurge: { success: false, deleted_records: 0 } } });
    });
    expect(screen.getByTestId('threat-pulse-purge-confirm')).toBeDefined();
    expect(screen.queryByText(/contributions purged from XTM Hub/)).toBeNull();
  });

  it('should read the settings again after a purge, so the page leaves the former contribution state', async () => {
    const relayEnv = renderSettings({ mode: 'contribute_and_read', access: 'full', enabled: true });
    fireEvent.click(await screen.findByTestId('threat-pulse-purge-button'));
    fireEvent.click(await screen.findByTestId('threat-pulse-purge-confirm'));
    act(() => {
      relayEnv.mock.resolveMostRecentOperation({ data: { pulsePurge: { success: true, deleted_records: 12 } } });
    });
    const operation = relayEnv.mock.getMostRecentOperation();
    expect(operation.request.node.operation.name).toBe('ThreatPulseSettingsQuery');
    expect(operation.request.variables).toEqual({ withMarkings: false });
  });

  it.each([
    ['in preview', IN_PREVIEW],
    ['turned off', { mode: 'off', access: 'off', enabled: false }],
  ])('should keep the right to purge %s, without contributing again', async (_, state) => {
    renderSettings(state);
    expect(await screen.findByTestId('threat-pulse-purge-button')).toBeDefined();
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

  it('should say that the contribution lapsed when XTM Hub reports it before the local access caught up', async () => {
    renderSettings({ ...LAPSED, access: 'full', readable: true });
    expect(await screen.findByTestId('threat-pulse-lapsed')).toBeDefined();
    expect(screen.getByText('Contribution lapsed - preview')).toBeDefined();
    expect(screen.queryByText('Contributing')).toBeNull();
  });

  it('should ask for the new consent when an upgrade changed it, and send nothing meanwhile', async () => {
    renderSettings({ mode: 'contribute_and_read', access: 'preview', enabled: false, consent_accepted_version: '2025-01-1', consent_date: '2025-01-10T09:00:00.000Z' });
    expect(await screen.findByTestId('threat-pulse-consent-renewal')).toBeDefined();
    expect(screen.getByText('Consent to renew - preview')).toBeDefined();
    expect(screen.queryByText('First contribution pending - preview')).toBeNull();
    expect(screen.queryByTestId('threat-pulse-configuration')).toBeNull();
    fireEvent.click(screen.getByText('Review the new consent'));
    expect(await screen.findByTestId('threat-pulse-consent-dialog')).toBeDefined();
  });

  it('should let a platform waiting for the new consent stop contributing without accepting it', async () => {
    const relayEnv = renderSettings({ mode: 'contribute_and_read', access: 'preview', enabled: false, consent_accepted_version: '2025-01-1', consent_date: '2025-01-10T09:00:00.000Z' });
    expect(await screen.findByTestId('threat-pulse-consent-renewal')).toBeDefined();
    fireEvent.click(screen.getByTestId('threat-pulse-stop-button'));
    expect(lastConfigureInput(relayEnv)).toMatchObject({ mode: 'preview' });
    expect(lastConfigureInput(relayEnv)).not.toHaveProperty('consent_version');
  });

  it('should say that the full experience waits for the first accepted contribution, never that it lapsed', async () => {
    renderSettings({ ...LAPSED, network: { ...SETTINGS.network, contribution_status: 'none', last_contribution_day: null } });
    expect(await screen.findByTestId('threat-pulse-pending')).toBeDefined();
    expect(screen.getByText('First contribution pending - preview')).toBeDefined();
    expect(screen.queryByTestId('threat-pulse-lapsed')).toBeNull();
  });

  it('should show the state without any action to a user who cannot manage XTM Hub', async () => {
    const { relayEnv } = testRender(<ThreatPulseSettings />, { userContext: analyst });
    const query = relayEnv.mock.getMostRecentOperation();
    // Without the marking list, which only an administrator of XTM Hub needs to pick exclusions
    expect(query.request.variables).toEqual({ withMarkings: false });
    act(() => {
      relayEnv.mock.resolve(query, MockPayloadGenerator.generate(query, { PulseSettings: () => ({ ...SETTINGS, ...IN_PREVIEW }) }));
    });
    expect(await screen.findByTestId('threat-pulse-preview-status')).toBeDefined();
    expect(screen.queryByTestId('threat-pulse-enable-button')).toBeNull();
    expect(screen.queryByTestId('threat-pulse-disable-button')).toBeNull();
  });

  it('should show the current exclusions to a user who cannot manage XTM Hub', async () => {
    renderSettings({
      mode: 'contribute_and_read',
      access: 'full',
      enabled: true,
      excluded_markings: [{ id: 'marking-internal', definition: 'INTERNAL', x_opencti_color: '#ff0000' }],
    }, analyst);
    expect(await screen.findByTestId('threat-pulse-configuration')).toBeDefined();
    expect(screen.getByText('INTERNAL')).toBeDefined();
  });
});
