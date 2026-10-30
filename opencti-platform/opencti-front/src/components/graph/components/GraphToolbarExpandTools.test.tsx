import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import { Formik } from 'formik';
import testRender from '../../../utils/tests/test-render';
import { graphNode } from '../../../utils/tests/graphTestData';
import type { InvestigationExpandFormProps } from '@components/workspaces/investigations/InvestigationExpandForm';
import GraphToolbarExpandTools from './GraphToolbarExpandTools';

const mocks = vi.hoisted(() => ({
  setIsExpandOpen: vi.fn(),
  setLinearProgress: vi.fn(),
  fetchQuery: vi.fn(),
  submitted: vi.fn(),
  values: {} as Parameters<InvestigationExpandFormProps['onSubmit']>[0],
}));
vi.mock('../GraphContext', () => ({
  useGraphContext: () => ({
    graphData: { links: [] },
    rawObjects: [],
    graphState: { selectedNodes: [graphNode({ id: 'actor' })], selectedLinks: [], isExpandOpen: true },
  }),
}));
vi.mock('../utils/useGraphInteractions', () => ({
  default: () => ({ setIsExpandOpen: mocks.setIsExpandOpen, setLinearProgress: mocks.setLinearProgress }),
}));
vi.mock('../../../relay/environment', () => ({ fetchQuery: mocks.fetchQuery }));
vi.mock('@components/workspaces/investigations/utils/useInvestigationState', () => ({ useInvestigationState: () => ({ containsExpandOp: () => false }) }));
vi.mock('@components/workspaces/investigations/dialog/InvestigationRollBackExpandDialog', () => ({ default: () => null }));
vi.mock('@components/workspaces/investigations/InvestigationExpandForm', () => ({
  default: ({ onSubmit, onReset }: InvestigationExpandFormProps) => (
    <Formik initialValues={mocks.values} onSubmit={(...args) => Promise.resolve(onSubmit(...args)).then(mocks.submitted)} onReset={onReset}>
      {({ submitForm }) => <button onClick={submitForm}>Expand</button>}
    </Formik>
  ),
}));

describe('GraphToolbarExpandTools', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.values = { entity_types: [], relationship_types: [], reset_filters: false };
  });

  it('closes the dialog as soon as the expansion starts', async () => {
    let resolveExpansion: (data: unknown) => void = () => {};
    const pending = new Promise((resolve) => {
      resolveExpansion = resolve;
    });
    mocks.fetchQuery.mockReturnValue({ toPromise: () => pending });
    mocks.values = { entity_types: [], relationship_types: [{ label: 'uses', value: 'uses' }], reset_filters: false };
    const onInvestigationExpand = vi.fn();
    const { user } = testRender(<GraphToolbarExpandTools onInvestigationExpand={onInvestigationExpand} />);
    await user.click(screen.getByRole('button', { name: 'Expand' }));
    await waitFor(() => expect(mocks.setIsExpandOpen).toHaveBeenCalledWith(false));
    expect(mocks.setIsExpandOpen).toHaveBeenCalledTimes(1);
    expect(mocks.setLinearProgress).toHaveBeenCalledWith(true);
    expect(onInvestigationExpand).not.toHaveBeenCalled();
    const node = { id: 'uses', from: { id: 'actor' }, to: { id: 'malware' } };
    resolveExpansion({ stixRelationships: { edges: [{ node }] } });
    await waitFor(() => expect(onInvestigationExpand).toHaveBeenCalledWith([node, node.to]));
    await waitFor(() => expect(mocks.submitted).toHaveBeenCalled());
    expect(mocks.setIsExpandOpen).toHaveBeenCalledTimes(1);
  });

  it('keeps the dialog open when no type is ticked', async () => {
    const { user } = testRender(<GraphToolbarExpandTools />);
    await user.click(screen.getByRole('button', { name: 'Expand' }));
    await waitFor(() => expect(mocks.submitted).toHaveBeenCalled());
    expect(mocks.setIsExpandOpen).not.toHaveBeenCalled();
    expect(mocks.fetchQuery).not.toHaveBeenCalled();
  });
});
