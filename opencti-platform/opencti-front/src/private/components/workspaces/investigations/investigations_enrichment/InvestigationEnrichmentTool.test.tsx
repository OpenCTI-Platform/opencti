import React from 'react';
import { act } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import testRender from '../../../../../utils/tests/test-render';
import InvestigationEnrichmentTool from './InvestigationEnrichmentTool';
import { GraphEntity } from '../../../../../components/graph/graph.types';

const mocks = vi.hoisted(() => ({
  drawer: vi.fn(),
  menuAction: vi.fn(),
  activateBoost: vi.fn(),
  canLaunch: true,
}));

vi.mock('react-relay', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-relay')>();
  return {
    ...actual,
    useQueryLoader: () => [{}, vi.fn()],
    usePreloadedQuery: () => ({
      workspace: { id: 'investigation-1', currentUserAccessRight: 'admin', enrichmentWorks: { edges: [] } },
    }),
  };
});

vi.mock('../../../../../components/graph/GraphContext', () => ({
  useGraphContext: () => ({ graphState: { selectedNodes: [], selectedLinks: [] } }),
}));

vi.mock('../../../../../utils/hooks/useIntervalBoostable', () => ({
  default: () => ({ activateBoost: mocks.activateBoost }),
}));

vi.mock('./useInvestigationEnrichmentRights', () => ({
  default: () => ({ canLaunch: mocks.canLaunch }),
}));

vi.mock('./InvestigationEnrichmentButton', () => ({ default: () => null }));

vi.mock('./InvestigationEnrichmentDrawer', () => ({
  default: (props: Record<string, unknown>) => {
    mocks.drawer(props);
    return null;
  },
}));

vi.mock('./InvestigationEnrichmentMenuAction', () => ({
  default: (props: Record<string, unknown>) => {
    mocks.menuAction(props);
    return null;
  },
}));

/**
 * Returns the props given to a mocked component on its last render.
 */
const lastProps = (mock: typeof mocks.drawer) => {
  const { calls } = mock.mock;
  return calls[calls.length - 1][0];
};

const renderTool = () => testRender(<InvestigationEnrichmentTool entity={{ id: 'investigation-1' } as GraphEntity} />);

describe('InvestigationEnrichmentTool', () => {
  it('opens the drawer on To review after an enrichment launched from the context menu, whatever tab it was left on', () => {
    renderTool();
    act(() => lastProps(mocks.drawer).onTabChange('done'));
    expect(lastProps(mocks.drawer)).toMatchObject({ open: false, tab: 'done' });

    act(() => lastProps(mocks.menuAction).onLaunched());

    expect(lastProps(mocks.drawer)).toMatchObject({ open: true, tab: 'toreview' });
    expect(mocks.activateBoost).toHaveBeenCalled();
  });

  it('gives the context menu action the investigation and the rights of the drawer launch', () => {
    mocks.canLaunch = false;
    try {
      renderTool();
      expect(lastProps(mocks.menuAction)).toMatchObject({ investigationId: 'investigation-1', canLaunch: false });
    } finally {
      mocks.canLaunch = true;
    }
  });
});
