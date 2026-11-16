import React from 'react';
import { act, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import testRender from '../../../../../utils/tests/test-render';
import InvestigationEnrichmentDrawer from './InvestigationEnrichmentDrawer';
import { Investigation, InvestigationWorkSorted } from './investigation-enrichment.types';

const mocks = vi.hoisted(() => ({
  launch: vi.fn(),
  expand: vi.fn(),
  rights: { canLaunch: true, canEdit: true, reviewDisabledReason: undefined as string | undefined },
}));

vi.mock('../../../../../utils/Security', () => ({
  default: ({ children }: { children: React.ReactNode }) => children,
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
vi.mock('./InvestigationEnrichmentExpand', () => ({
  default: (props: Record<string, unknown>) => {
    mocks.expand(props);
    return null;
  },
}));
vi.mock('./InvestigationEnrichmentAddAllDialog', () => ({ default: () => null }));

vi.mock('./useInvestigationEnrichmentExpand', () => ({
  default: () => ({ graphIds: new Set(), expandWorks: vi.fn() }),
}));

vi.mock('./useInvestigationEnrichmentRights', () => ({
  default: () => mocks.rights,
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

const renderDrawer = (onLaunched: () => void, askRefresh: () => void, drawerWorks = works) => testRender(
  <InvestigationEnrichmentDrawer
    open
    onClose={() => {}}
    tab="toreview"
    onTabChange={() => {}}
    investigation={{ id: 'investigation-1', currentUserAccessRight: 'admin' } as Investigation}
    works={drawerWorks}
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

  it('disables the review of all results for an editor who cannot review them, saying why', async () => {
    mocks.rights = { canLaunch: false, canEdit: true, reviewDisabledReason: 'Missing capabilities' };
    const toReview = new Map([['ip-1', [{ id: 'work-1', errors: [] } as never]]]);
    const { user } = renderDrawer(vi.fn(), vi.fn(), { ...works, toreview: toReview });

    const reviewAll = screen.getByRole('button', { name: 'Review all (1)' });
    expect(reviewAll).toHaveAttribute('aria-disabled', 'true');
    expect(reviewAll).toHaveAccessibleDescription('Missing capabilities');
    await user.click(reviewAll);
    expect(mocks.expand).not.toHaveBeenLastCalledWith(expect.objectContaining({ works: [expect.anything()] }));
  });

  it('opens the review of all results for an editor allowed to review them', async () => {
    mocks.rights = { canLaunch: true, canEdit: true, reviewDisabledReason: undefined };
    const work = { id: 'work-1', errors: [] } as never;
    const { user } = renderDrawer(vi.fn(), vi.fn(), { ...works, toreview: new Map([['ip-1', [work]]]) });

    await user.click(screen.getByRole('button', { name: 'Review all (1)' }));

    const { calls } = mocks.expand.mock;
    expect(calls[calls.length - 1][0]).toEqual(expect.objectContaining({ works: [work], canEdit: true, reviewDisabledReason: undefined }));
  });
});
