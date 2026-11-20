import React from 'react';
import { act } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import testRender from '../../../../../utils/tests/test-render';
import InvestigationEnrichmentDrawer from './InvestigationEnrichmentDrawer';
import { Investigation, InvestigationWorkSorted } from './investigation-enrichment.types';

const mocks = vi.hoisted(() => ({
  launch: vi.fn(),
}));

vi.mock('../../../common/drawer/Drawer', () => ({
  default: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

vi.mock('./InvestigationEnrichmentLaunch', () => ({
  default: (props: Record<string, unknown>) => {
    mocks.launch(props);
    return null;
  },
}));

vi.mock('./InvestigationEnrichmentDrawerTabs', () => ({ default: () => null }));
vi.mock('./InvestigationEnrichmentWorkList', () => ({ default: () => null }));
vi.mock('./InvestigationEnrichmentExpand', () => ({ default: () => null }));
vi.mock('./InvestigationEnrichmentAddAllDialog', () => ({ default: () => null }));

vi.mock('./useInvestigationEnrichmentExpand', () => ({
  default: () => ({ graphIds: new Set(), expandWorks: vi.fn() }),
}));

vi.mock('./useInvestigationEnrichmentRights', () => ({
  default: () => ({ canLaunch: true, canEdit: true }),
}));

vi.mock('../../../../../utils/hooks/useApiMutation', () => ({
  default: () => [vi.fn()],
}));

vi.mock('../../../../../components/graph/GraphContext', () => ({
  useGraphContext: () => ({
    graphState: { selectedNodes: [{ id: 'ip-1' }], selectedLinks: [] },
  }),
}));

/**
 * Returns the props given to the launch form on its last render.
 */
const lastLaunchProps = () => {
  const { calls } = mocks.launch.mock;
  return calls[calls.length - 1][0];
};

const works: InvestigationWorkSorted = { ongoing: new Map(), done: new Map(), toreview: new Map() };

const renderDrawer = (onLaunched: () => void, askRefresh: () => void) => testRender(
  <InvestigationEnrichmentDrawer
    open
    onClose={() => {}}
    tab="toreview"
    onTabChange={() => {}}
    investigation={{ id: 'investigation-1', currentUserAccessRight: 'admin' } as Investigation}
    works={works}
    isSending={false}
    onLaunched={onLaunched}
    askRefresh={askRefresh}
  />,
);

describe('InvestigationEnrichmentDrawer', () => {
  it('reports an enrichment launched from the drawer once the API accepted it, and refreshes the works', () => {
    const onLaunched = vi.fn();
    const askRefresh = vi.fn();
    renderDrawer(onLaunched, askRefresh);

    act(() => lastLaunchProps().onCompleted());

    expect(onLaunched).toHaveBeenCalledTimes(1);
    expect(askRefresh).toHaveBeenCalledTimes(1);
  });
});
