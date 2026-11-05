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
  works: [] as unknown[],
}));

vi.mock('react-relay', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-relay')>();
  return {
    ...actual,
    useQueryLoader: () => [{}, vi.fn()],
    usePreloadedQuery: () => ({
      workspace: { id: 'investigation-1', currentUserAccessRight: 'admin', enrichmentWorks: { edges: mocks.works } },
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

  it('shows the drawer launch as sending once an enrichment is launched from the context menu', () => {
    renderTool();
    expect(lastProps(mocks.drawer)).toMatchObject({ isSending: false });

    act(() => lastProps(mocks.menuAction).onLaunched());

    expect(lastProps(mocks.drawer)).toMatchObject({ isSending: true });
  });

  it('shows the drawer launch as sending once launched from the drawer, until the count of works changes', () => {
    const work = { node: { id: 'work-1', status: 'progress', investigation_status: null, errors: [], event_source_id: 'ip-1' } };
    try {
      const { rerender } = renderTool();
      act(() => lastProps(mocks.drawer).onLaunched());
      expect(lastProps(mocks.drawer)).toMatchObject({ isSending: true });

      mocks.works = [work];
      rerender(<InvestigationEnrichmentTool entity={{ id: 'investigation-1' } as GraphEntity} />);

      expect(lastProps(mocks.drawer)).toMatchObject({ isSending: false });
    } finally {
      mocks.works = [];
    }
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
