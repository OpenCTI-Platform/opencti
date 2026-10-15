import React from 'react';
import { fireEvent, screen } from '@testing-library/react';
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
 * Returns the ENRICHMENT actions given to the background task launcher on its last render.
 */
const lastLaunchedActions = () => {
  const { calls } = mocks.backgroundTaskLaunch.mock;
  return calls[calls.length - 1][0].actions;
};

describe('InvestigationEnrichmentLaunch', () => {
  it('links the bulk enrichment to the investigation', () => {
    testRender(
      <InvestigationEnrichmentLaunch
        investigationId="investigation-1"
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
});
