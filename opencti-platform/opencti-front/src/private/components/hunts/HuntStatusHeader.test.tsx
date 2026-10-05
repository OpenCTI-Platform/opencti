import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, screen, within } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';
import { MESSAGING$ } from '../../../relay/environment';
import { BYPASS } from '../../../utils/hooks/useGranted';
import HuntStatusHeader, { HuntReadinessChecklist, huntPrimaryStatusAction } from './HuntStatusHeader';
import { huntLogicMissingSentence } from './HuntLogic';
import { HUNT_STATUS_MEANINGS, HUNT_STATUSES } from './hunt-utils';

vi.mock('react-relay', async (importOriginal) => {
  const original = await importOriginal<typeof import('react-relay')>();
  return { ...original, useFragment: (_fragment: unknown, data: unknown) => data };
});

vi.mock('../../../relay/environment', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../../relay/environment')>();
  return {
    ...original,
    MESSAGING$: { ...original.MESSAGING$, notifyError: vi.fn(), notifyRelayError: vi.fn(), notifySuccess: vi.fn() },
  };
});

const item = (key: string, status: string, template: string, values: Record<string, string> = {}) => ({
  key,
  status,
  template,
  values: Object.entries(values).map(([name, value]) => ({ name, value })),
  message: template,
}) as never;

describe('Hunt status header', () => {
  it('gives each status its primary action', () => {
    expect(huntPrimaryStatusAction('draft')).toEqual({ to: 'active', label: 'Activate' });
    expect(huntPrimaryStatusAction('active')).toEqual({ to: 'paused', label: 'Pause' });
    expect(huntPrimaryStatusAction('paused')).toEqual({ to: 'active', label: 'Resume' });
    expect(huntPrimaryStatusAction('retired')).toEqual({ to: 'draft', label: 'Reopen as draft' });
    expect(huntPrimaryStatusAction('unknown')).toBeNull();
  });

  it('explains every status in one line', () => {
    HUNT_STATUSES.forEach((status) => expect(HUNT_STATUS_MEANINGS[status].length).toBeGreaterThan(10));
    expect(HUNT_STATUS_MEANINGS.draft).toBe('The hunt is being written; it never runs.');
  });

  it('lists each readiness item with the place to fix the unmet ones', () => {
    testRender(
      <HuntReadinessChecklist
        huntId="hunt-id"
        items={[
          item('logic', 'unmet', 'Add a Sigma rule or a native query'),
          item('connector', 'unmet', 'No hunt connector can run it on the platforms of its scope: deploy a hunt connector or widen the scope'),
          item('schedule', 'met', 'Manual: it runs when you click Run now'),
          item('scope', 'met', 'Runs on {platforms}', { platforms: 'Splunk Production' }),
        ]}
      />,
    );
    const logic = screen.getByTestId('hunt-readiness-logic');
    expect(logic).toHaveAttribute('data-status', 'unmet');
    expect(within(logic).getByText('Add a Sigma rule or a native query')).toBeInTheDocument();
    expect(within(logic).getByTestId('hunt-readiness-open-logic')).toHaveAttribute('href', '/dashboard/defense/hunts/hunt-id/logic');
    expect(within(screen.getByTestId('hunt-readiness-connector')).getByTestId('hunt-readiness-open-connectors')).toBeInTheDocument();
    // The values the platform sends fill the sentence; a met item offers no action
    const scope = screen.getByTestId('hunt-readiness-scope');
    expect(within(scope).getByText('Runs on Splunk Production')).toBeInTheDocument();
    expect(within(scope).queryByRole('button')).toBeNull();
  });

  it('words a missing logic as the platform does', () => {
    expect(huntLogicMissingSentence('telemetry', '', [])).toBe('Add a Sigma rule or a native query');
    expect(huntLogicMissingSentence('telemetry', '', [{ platform: 'internet' }])).toBe('Add a Sigma rule or a native query');
    expect(huntLogicMissingSentence('telemetry', 'title: x', [])).toBeNull();
    expect(huntLogicMissingSentence('telemetry', '', [{ platform: 'splunk' }])).toBeNull();
    expect(huntLogicMissingSentence('infrastructure', '', [{ platform: 'splunk' }])).toBe('Add a native query for the internet platform');
    expect(huntLogicMissingSentence('infrastructure', '', [{ platform: 'internet' }])).toBeNull();
  });
});

describe('Hunt status header dialogs', () => {
  const hunt = {
    id: 'hunt-1',
    hunt_status: 'active',
    hunt_type: 'telemetry',
    time_window_hours: 24,
    scopePlatforms: [],
    readiness: { ready: true, items: [] },
  };
  const renderHeader = () => testRender(<HuntStatusHeader data={hunt as never} />, {
    userContext: createMockUserContext({ me: { name: 'admin', user_email: 'admin@opencti.io', capabilities: [{ name: BYPASS }] } as never }),
  });

  afterEach(() => vi.clearAllMocks());

  it('counts the readiness points that need attention in the singular and the plural', () => {
    const warning = (key: string) => item(key, 'warning', 'The hunt connector has not answered recently');
    const { unmount } = testRender(<HuntStatusHeader data={{ ...hunt, readiness: { ready: true, items: [warning('connector')] } } as never} />);
    expect(screen.getByTestId('hunt-readiness-summary')).toHaveTextContent('Ready to run, 1 point needs attention');
    unmount();
    testRender(<HuntStatusHeader data={{ ...hunt, readiness: { ready: true, items: [warning('connector'), warning('scope')] } } as never} />);
    expect(screen.getByTestId('hunt-readiness-summary')).toHaveTextContent('Ready to run, 2 points need attention');
  });

  // The global snackbar renders under the overlay of a design-system dialog: an error sent there is never seen
  it('shows why a hunt could not be retired inside the confirmation', async () => {
    const { user, relayEnv } = renderHeader();
    await user.click(screen.getByTestId('hunt-status-to-retired'));
    await user.click(screen.getByTestId('hunt-status-retire-confirm'));
    await act(async () => {
      relayEnv.mock.resolveMostRecentOperation({ data: { huntFieldPatch: null }, errors: [{ message: 'The hunt is locked by a running import' }] } as never);
    });
    const dialog = screen.getByTestId('hunt-status-retire-dialog');
    expect(within(dialog).getByTestId('hunt-status-retire-error')).toHaveTextContent('The hunt is locked by a running import');
    expect(MESSAGING$.notifyError).not.toHaveBeenCalled();
    // Reopening the confirmation starts clean
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await user.click(screen.getByTestId('hunt-status-to-retired'));
    expect(screen.queryByTestId('hunt-status-retire-error')).not.toBeInTheDocument();
  });

  it('shows a failed retire request inside the confirmation', async () => {
    const { user, relayEnv } = renderHeader();
    await user.click(screen.getByTestId('hunt-status-to-retired'));
    await user.click(screen.getByTestId('hunt-status-retire-confirm'));
    await act(async () => {
      relayEnv.mock.rejectMostRecentOperation(new Error('Network error'));
    });
    expect(within(screen.getByTestId('hunt-status-retire-dialog')).getByTestId('hunt-status-retire-error')).toHaveTextContent('The hunt could not be retired');
    // The snackbar would repeat the error behind the overlay, then once the dialog closes
    expect(MESSAGING$.notifyRelayError).not.toHaveBeenCalled();
  });

  it('shows why the query preview could not start inside its dialog', async () => {
    const { user, relayEnv } = renderHeader();
    await user.click(screen.getByTestId('hunt-query-preview-open'));
    await act(async () => {
      relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
        Query: () => ({
          huntConnectors: [{
            id: 'connector-1',
            name: 'Splunk Hunt',
            platform: 'splunk',
            supports_preview: true,
            supports_indicators: true,
            securityPlatform: { id: 'platform-1', name: 'Splunk Production' },
          }],
        }),
      }));
    });
    // The preview starts on its own in the dialog
    await act(async () => {
      relayEnv.mock.resolveMostRecentOperation({ data: { huntTestQuery: null }, errors: [{ message: 'No live hunt connector serves a security platform of this hunt you can access' }] } as never);
    });
    const dialog = screen.getByRole('dialog');
    expect(within(dialog).getByTestId('hunt-preview-error')).toHaveTextContent('No live hunt connector serves a security platform of this hunt you can access');
    expect(MESSAGING$.notifyError).not.toHaveBeenCalled();
    // A failed request reads the same, where the preview used to fall back to idle without a word
    await user.click(within(dialog).getByTestId('hunt-translation-preview-start'));
    await act(async () => {
      relayEnv.mock.rejectMostRecentOperation(new Error('Network error'));
    });
    expect(within(dialog).getByTestId('hunt-preview-error')).toHaveTextContent('The query preview could not be started');
    expect(MESSAGING$.notifyRelayError).not.toHaveBeenCalled();
  });
});
