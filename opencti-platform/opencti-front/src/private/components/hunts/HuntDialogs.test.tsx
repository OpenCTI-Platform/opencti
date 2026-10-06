import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import testRender from '../../../utils/tests/test-render';
import HuntGuidedCreation from './HuntGuidedCreation';
import HuntPlanDialog from './HuntPlanDialog';
import HuntRunStart from './runs/HuntRunStart';

const PLATFORM = { id: 'platform-1', entity_type: 'SecurityPlatform', representative: { main: 'Google SecOps - production' } };

vi.mock('../../../relay/environment', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../../relay/environment')>();
  return {
    ...original,
    fetchQuery: (query: { params?: { name?: string } }) => ({
      toPromise: () => Promise.resolve(query.params?.name === 'HuntEntitiesFieldSearchQuery'
        ? { stixCoreObjects: { edges: [{ node: PLATFORM }] } }
        : {}),
      // The hunting configuration keeps its defaults
      subscribe: () => ({ unsubscribe: () => {} }),
    }),
  };
});

vi.mock('../../../utils/ai/agentApi', () => ({ fetchAgentsForIntent: () => Promise.resolve([]) }));
// The Generate with AI of the Sigma step carries the Enterprise Edition chip on a Community Edition platform
vi.mock('@components/common/entreprise_edition/EEChip', () => ({ default: () => <span data-testid="hunt-ee-chip">EE</span> }));

const SIGMA_RULE = 'title: Encoded PowerShell\nlogsource:\n  product: windows\ndetection:\n  selection:\n    CommandLine|contains: " -enc "\n  condition: selection';

const huntConnector = (supportsIndicators: boolean) => ({
  id: 'connector-1',
  name: 'Google SecOps Hunt',
  platform: 'google_secops',
  supports_indicators: supportsIndicators,
  securityPlatform: { id: PLATFORM.id, name: PLATFORM.representative.main },
});

describe('Hunt dialogs', () => {
  afterEach(() => vi.clearAllMocks());

  it('picks a security platform inside the modal guided creation, with no type-scope menu to freeze it', async () => {
    const { user, relayEnv } = testRender(<HuntGuidedCreation kind="sigma" open onClose={() => undefined} />);
    const dialog = screen.getByRole('dialog');
    fireEvent.change(within(dialog).getByTestId('hunt-guided-sigma-editor').querySelector('textarea') as HTMLTextAreaElement, { target: { value: SIGMA_RULE } });
    await user.click(within(dialog).getByTestId('hunt-guided-next'));
    await act(async () => {
      relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
        Query: () => ({ huntConnectors: [huntConnector(false)] }),
      }));
    });
    const scope = within(dialog).getByTestId('hunt-guided-scope');
    // The palette button of the MUI field opened a focus-trapping popover inside the dialog focus scope
    expect(within(scope).queryByRole('button', { name: 'Open menu' })).not.toBeInTheDocument();
    await user.click(within(scope).getByRole('combobox', { name: /Security platforms/ }));
    // A portalled MUI popper inherits the pointer-events: none the modal dialog sets on the body: user-event refuses that click
    await user.click(await screen.findByRole('option', { name: /Google SecOps - production/ }));
    await waitFor(() => expect(within(scope).getByText('Google SecOps - production')).toBeInTheDocument());
  });

  it('decides to activate the guided hunt only once the connectors of its scope are counted', async () => {
    const { user, relayEnv } = testRender(<HuntGuidedCreation kind="sigma" open onClose={() => undefined} />);
    const dialog = screen.getByRole('dialog');
    fireEvent.change(within(dialog).getByTestId('hunt-guided-sigma-editor').querySelector('textarea') as HTMLTextAreaElement, { target: { value: SIGMA_RULE } });
    await user.click(within(dialog).getByTestId('hunt-guided-next'));
    // The lookup of the scope step is still pending: its count would be a guess
    expect(within(dialog).getByTestId('hunt-guided-next')).toBeDisabled();
    await act(async () => {
      relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
        Query: () => ({ huntConnectors: [huntConnector(false)] }),
      }));
    });
    await waitFor(() => expect(within(dialog).getByTestId('hunt-guided-next')).toBeEnabled());
    await user.click(within(dialog).getByTestId('hunt-guided-next'));
    expect(within(dialog).getByTestId('hunt-guided-submit')).toHaveTextContent('Activate and run now');
  });

  it('picks what to plan from inside the modal plan dialog', async () => {
    const { user } = testRender(<HuntPlanDialog open onClose={() => undefined} entityIds={[]} />);
    const subjects = await screen.findByTestId('hunt-plan-subjects');
    expect(within(subjects).queryByRole('button', { name: 'Open menu' })).not.toBeInTheDocument();
    await user.click(within(subjects).getByRole('combobox', { name: /Plan from/ }));
    await user.click(await screen.findByRole('option', { name: /Google SecOps - production/ }));
    await waitFor(() => expect(screen.getByTestId('hunt-plan-submit')).toBeEnabled());
  });
});

describe('Run the hunt now', () => {
  const hunt = { id: 'hunt-1', hunt_status: 'active', hunt_type: 'telemetry', time_window_hours: 24, scopePlatforms: [] };

  const openRunDialog = async (connectors: ReturnType<typeof huntConnector>[]) => {
    const rendered = testRender(<HuntRunStart hunt={hunt} />);
    await rendered.user.click(screen.getByTestId('hunt-run-start'));
    await act(async () => {
      rendered.relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
        Query: () => ({ huntConnectors: connectors }),
      }));
    });
    return rendered;
  };

  it('shows the error of the platform inside the dialog, above its overlay', async () => {
    const { user, relayEnv } = await openRunDialog([huntConnector(false)]);
    await user.click(screen.getByTestId('hunt-run-start-submit'));
    await act(async () => {
      relayEnv.mock.resolveMostRecentOperation({
        data: { huntRunStart: null },
        errors: [{ message: 'No live hunt connector serves a security platform of this hunt you can access' }],
      } as never);
    });
    const dialog = screen.getByTestId('hunt-run-start-dialog');
    expect(within(dialog).getByTestId('hunt-run-start-error')).toHaveTextContent('No live hunt connector serves a security platform of this hunt you can access');
    expect(within(dialog).getByTestId('hunt-run-start-submit')).toBeEnabled();
  });

  it('disables Run while the dialog states that no hunt connector can run the hunt', async () => {
    await openRunDialog([]);
    expect(screen.getByTestId('hunt-run-start-no-connector')).toBeInTheDocument();
    expect(screen.getByTestId('hunt-run-start-submit')).toBeDisabled();
  });
});
