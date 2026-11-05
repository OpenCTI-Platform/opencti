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
  default: ({ onChange }: { onChange: (connectorIds: string[]) => void }) => (
    <button
      type="button"
      onClick={() => onChange(['connector-1'])}
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
 * Renders the form with a count of works, a connector selected, and the enrichment launched.
 */
const renderLaunched = () => {
  const view = testRender(
    <InvestigationEnrichmentLaunch
      investigationId="investigation-1"
      onCompleted={() => {}}
      worksCount={2}
    />,
  );
  fireEvent.click(screen.getByText('select connector'));
  act(() => lastLaunchProps().onLaunch());
  return view;
};

describe('InvestigationEnrichmentLaunch', () => {
  it('links the bulk enrichment to the investigation', () => {
    testRender(
      <InvestigationEnrichmentLaunch
        investigationId="investigation-1"
        onCompleted={console.log}
        worksCount={0}
      />,
    );

    fireEvent.click(screen.getByText('select connector'));

    expect(lastLaunchedActions()).toEqual([{
      type: 'ENRICHMENT',
      context: {
        values: ['connector-1'],
        options: { investigationId: 'investigation-1' },
      },
    }]);
  });

  it('shows a spinner next to the label once launched, without disabling the button', () => {
    renderLaunched();

    const button = screen.getByRole('button', { name: 'Enrich' });
    expect(button).toHaveAttribute('aria-busy', 'true');
    expect(button).toBeEnabled();
  });

  it('stops showing the spinner once the count of works changed', () => {
    const { rerender } = renderLaunched();

    rerender(
      <InvestigationEnrichmentLaunch
        investigationId="investigation-1"
        onCompleted={() => {}}
        worksCount={3}
      />,
    );

    expect(screen.getByRole('button', { name: 'Enrich' })).not.toHaveAttribute('aria-busy');
  });
});
