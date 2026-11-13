import React from 'react';
import { act, fireEvent, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import testRender from '../../../../../utils/tests/test-render';
import InvestigationEnrichmentLaunch from './InvestigationEnrichmentLaunch';

const mocks = vi.hoisted(() => ({
  backgroundTaskLaunch: vi.fn(),
}));

vi.mock('../../../common/background_task/BackgroundTaskLaunch', () => ({
  default: (props: Record<string, unknown>) => {
    mocks.backgroundTaskLaunch(props);
    return null;
  },
}));

vi.mock('../../../data/connectors/EnrichmentConnectorSelection', () => ({
  default: ({ onChange }: { onChange: (connectors: { id: string; name: string }[]) => void }) => (
    <button
      type="button"
      onClick={() => onChange([{ id: 'connector-1', name: 'Coucou Enrichment' }])}
    >
      select connector
    </button>
  ),
}));

vi.mock('../../../../../components/graph/GraphContext', () => ({
  useGraphContext: () => ({
    graphState: {
      selectedNodes: [{ id: 'node-1', label: 'APT1', entity_type: 'Intrusion-Set' }],
      selectedLinks: [],
    },
  }),
}));

/**
 * Returns the props given to the background task launcher on its last render.
 */
const lastLaunchProps = () => {
  const { calls } = mocks.backgroundTaskLaunch.mock;
  return calls[calls.length - 1][0];
};

/**
 * Returns the ENRICHMENT actions given to the background task launcher on its last render.
 */
const lastLaunchedActions = () => lastLaunchProps().actions;

/**
 * Renders the form, sending an enrichment or not, with a connector selected.
 */
const renderForm = ({ isSending = false, onCompleted = () => {} }: { isSending?: boolean; onCompleted?: () => void } = {}) => {
  const view = testRender(
    <InvestigationEnrichmentLaunch
      investigationId="investigation-1"
      onCompleted={onCompleted}
      isSending={isSending}
    />,
  );
  fireEvent.click(screen.getByText('select connector'));
  return view;
};

describe('InvestigationEnrichmentLaunch', () => {
  it('links the bulk enrichment to the investigation, naming the connector for the launcher', () => {
    renderForm();

    expect(lastLaunchedActions()).toEqual([{
      type: 'ENRICHMENT',
      context: {
        values: [{ id: 'connector-1', value: 'Coucou Enrichment' }],
        options: { investigationId: 'investigation-1' },
      },
    }]);
  });

  it('reports the enrichment once the API accepted it, so that the button shows it is sending', () => {
    const onCompleted = vi.fn();
    renderForm({ onCompleted });

    act(() => lastLaunchProps().onLaunch());
    expect(onCompleted).not.toHaveBeenCalled();

    act(() => lastLaunchProps().onCompleted());
    expect(onCompleted).toHaveBeenCalledTimes(1);
  });

  it('does not report an enrichment the API rejected, so that the button does not stay busy', () => {
    const onCompleted = vi.fn();
    renderForm({ onCompleted });

    act(() => lastLaunchProps().onLaunch());
    // The mutation failed: onCompleted never comes, the user closes the launcher.
    act(() => lastLaunchProps().onClose());

    expect(onCompleted).not.toHaveBeenCalled();
  });

  it('shows a spinner next to the label while sending, without disabling the button', () => {
    renderForm({ isSending: true });

    const button = screen.getByRole('button', { name: 'Enrich' });
    expect(button).toHaveAttribute('aria-busy', 'true');
    expect(button).toBeEnabled();
  });

  it('shows no spinner when not sending', () => {
    renderForm();

    expect(screen.getByRole('button', { name: 'Enrich' })).not.toHaveAttribute('aria-busy');
  });
});
