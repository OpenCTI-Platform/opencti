import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, screen } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import { THREAT_PULSE_PREVIEW_BANNER_DISMISSED_BUS, threatPulsePreviewBannerDismissKey } from '../../../../utils/bannerConstants';
import { readThreatPulsePreviewBannerVisible } from '../../../../utils/bannerUtils';
import { dispatch } from '../../../../utils/hooks/useBus';
import useTopBanner from '../../../../utils/hooks/useTopBanner';
import { TOP_BANNER_HEIGHT } from '../../../../components/TopBanner';
import ThreatPulsePreviewBanner, { isPreviewBannerWindowOpen } from './ThreatPulsePreviewBanner';

const administrator = createMockUserContext({ me: { id: 'admin', name: 'admin', capabilities: [{ name: 'BYPASS' }] } });
const analyst = createMockUserContext({ me: { id: 'analyst', name: 'analyst', capabilities: [{ name: 'KNOWLEDGE' }] } });

const HOUR = 60 * 60 * 1000;
const hoursAgo = (hours: number) => new Date(Date.now() - hours * HOUR).toISOString();

const renderBanner = (pulseStatus: Record<string, unknown>, userContext = administrator) => {
  const { relayEnv } = testRender(<ThreatPulsePreviewBanner />, { userContext });
  act(() => {
    relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
      PulseStatus: () => pulseStatus,
    }));
  });
  return relayEnv;
};

describe('isPreviewBannerWindowOpen', () => {
  it('should be open during the first day the preview matches objects only', () => {
    const now = Date.parse('2026-10-03T12:00:00.000Z');
    expect(isPreviewBannerWindowOpen('2026-10-03T00:00:00.000Z', now)).toBe(true);
    expect(isPreviewBannerWindowOpen('2026-10-02T12:00:01.000Z', now)).toBe(true);
    expect(isPreviewBannerWindowOpen('2026-10-02T12:00:00.000Z', now)).toBe(false);
    expect(isPreviewBannerWindowOpen(null, now)).toBe(false);
    expect(isPreviewBannerWindowOpen('not a date', now)).toBe(false);
  });
});

describe('ThreatPulsePreviewBanner', () => {
  afterEach(() => localStorage.clear());

  it('should announce the preview with the local count and the unlock step to an administrator', async () => {
    renderBanner({ access: 'preview', preview_entities: 42, preview_since: hoursAgo(2) });
    expect(await screen.findByText('Threat Pulse preview: 42 of your objects are seen across the community.')).toBeDefined();
    expect(screen.getByText('Set up contribution')).toBeDefined();
  });

  it('should use the singular for one matched object', async () => {
    renderBanner({ access: 'preview', preview_entities: 1, preview_since: hoursAgo(2) });
    expect(await screen.findByText('Threat Pulse preview: 1 of your objects is seen across the community.')).toBeDefined();
  });

  it('should tell a non-administrator whom to ask, without the button', async () => {
    renderBanner({ access: 'preview', preview_entities: 3, preview_since: hoursAgo(1) }, analyst);
    expect(await screen.findByText(/Ask your administrator to turn on contribution in Settings > Filigran Experience\./)).toBeDefined();
    expect(screen.queryByText('Set up contribution')).toBeNull();
  });

  it('should hide at the end of the first day while the page stays open', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date'], shouldAdvanceTime: true });
    try {
      renderBanner({ access: 'preview', preview_entities: 42, preview_since: hoursAgo(23) });
      expect(await screen.findByText(/Threat Pulse preview:/)).toBeDefined();
      act(() => {
        vi.advanceTimersByTime(HOUR + 1000);
      });
      expect(screen.queryByText(/Threat Pulse preview:/)).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it('should stay hidden after the first day, without a match, or outside the preview', () => {
    renderBanner({ access: 'preview', preview_entities: 42, preview_since: hoursAgo(30) });
    expect(screen.queryByText(/Threat Pulse preview:/)).toBeNull();
    renderBanner({ access: 'preview', preview_entities: 0, preview_since: null });
    expect(screen.queryByText(/Threat Pulse preview:/)).toBeNull();
    renderBanner({ access: 'full', preview_entities: 0, preview_since: null });
    expect(screen.queryByText(/Threat Pulse preview:/)).toBeNull();
  });

  it('should never load once the user dismissed it', () => {
    localStorage.setItem(threatPulsePreviewBannerDismissKey('admin'), 'true');
    const { relayEnv } = testRender(<ThreatPulsePreviewBanner />, { userContext: administrator });
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
    expect(screen.queryByText(/Threat Pulse preview:/)).toBeNull();
  });

  it('should give the top offset of the visible banner to a page mounted after it, until it is dismissed', async () => {
    const TopOffset = () => {
      const { height, showThreatPulsePreviewBanner } = useTopBanner();
      return <div data-testid="top-offset">{`${showThreatPulsePreviewBanner}:${height}`}</div>;
    };
    renderBanner({ access: 'preview', preview_entities: 42, preview_since: hoursAgo(2) });
    expect(await screen.findByText(/Threat Pulse preview:/)).toBeDefined();
    expect(readThreatPulsePreviewBannerVisible()).toBe(true);
    // A lazy route component mounted once the banner already reported its visibility
    testRender(<TopOffset />, { userContext: administrator });
    expect(screen.getByTestId('top-offset').textContent).toBe(`true:${TOP_BANNER_HEIGHT}`);
    act(() => {
      dispatch(THREAT_PULSE_PREVIEW_BANNER_DISMISSED_BUS, true);
    });
    expect(readThreatPulsePreviewBannerVisible()).toBe(false);
    expect(screen.getByTestId('top-offset').textContent).toMatch(/^false:/);
  });
});
