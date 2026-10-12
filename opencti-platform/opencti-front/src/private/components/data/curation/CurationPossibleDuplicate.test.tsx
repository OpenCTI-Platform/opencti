import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import CurationPossibleDuplicate from './CurationPossibleDuplicate';

const { lookup, draft } = vi.hoisted(() => ({
  lookup: vi.fn(),
  draft: { current: undefined as { id: string } | undefined },
}));

vi.mock('../../../../relay/environment', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../relay/environment')>();
  return {
    ...actual,
    fetchQuery: (_query: unknown, variables: Variables) => ({ toPromise: () => lookup(variables.merges.filters[0].values[0], variables) }),
  };
});

vi.mock('../../../../utils/hooks/useDraftContext', () => ({ default: () => draft.current }));

interface Variables {
  merges: { filters: Array<{ key: string[]; values: string[] }> };
  aliases: { filters: Array<{ key: string[]; values: string[] }> };
}

const proposalOf = (entityId: string, otherName: string, title: string) => ({
  id: `proposal-${entityId}`,
  confidence_score: 0.92,
  subject_ids: [entityId, `other-${entityId}`],
  subject_names: ['Subject', otherName],
  created_at: '2026-10-06T08:00:00.000Z',
  explanation: { title: { template: title, values: null, text: title } },
});

const pageOf = (proposals: Array<ReturnType<typeof proposalOf>>, globalCount = proposals.length) => ({
  pageInfo: { globalCount },
  edges: proposals.map((node) => ({ node })),
});

const mergeProposalOf = (entityId: string, otherName: string) => ({
  merges: pageOf([proposalOf(entityId, otherName, 'Merge the entities')]),
  aliases: pageOf([]),
});

describe('CurationPossibleDuplicate', () => {
  beforeEach(() => {
    lookup.mockReset();
    draft.current = undefined;
  });

  it('never shows the proposals of the previous entity while those of the new one load', async () => {
    let answerSecond: (value: unknown) => void = () => {};
    lookup.mockImplementation((id: string) => (id === 'first'
      ? Promise.resolve(mergeProposalOf('first', 'Fancy Bear'))
      : new Promise((resolve) => {
          answerSecond = resolve;
        })));
    const { rerender } = testRender(<CurationPossibleDuplicate entityId="first" />);
    expect(await screen.findByText('Possible duplicate of Fancy Bear')).toBeInTheDocument();

    rerender(<CurationPossibleDuplicate entityId="second" />);
    expect(screen.queryByTestId('curation-possible-duplicate')).toBeNull();

    await act(async () => answerSecond(mergeProposalOf('second', 'Sofacy')));
    expect(await screen.findByText('Possible duplicate of Sofacy')).toBeInTheDocument();
  });

  it('shows each chip from the open proposals of its own kind', async () => {
    lookup.mockResolvedValue({ merges: pageOf([]), aliases: pageOf([proposalOf('first', 'Sofacy', 'Add the aliases')]) });
    testRender(<CurationPossibleDuplicate entityId="first" />);
    expect(await screen.findByTestId('curation-aliases-to-review')).toBeInTheDocument();
    expect(screen.queryByTestId('curation-possible-duplicate')).toBeNull();
    const [, variables] = lookup.mock.calls[0] as [string, Variables];
    const kindOf = (group: Variables['merges']) => group.filters.find(({ key }) => key[0] === 'proposal_kind')?.values;
    expect(kindOf(variables.merges)).toEqual(['merge']);
    expect(kindOf(variables.aliases)).toEqual(['alias']);
  });

  it('counts every open merge proposal of the entity, not only the most confident one it reads', async () => {
    lookup.mockResolvedValue({ merges: pageOf([proposalOf('first', 'Fancy Bear', 'Merge the entities')], 73), aliases: pageOf([]) });
    testRender(<CurationPossibleDuplicate entityId="first" />);
    expect(await screen.findByText('73 possible duplicates')).toBeInTheDocument();
  });

  it('shows nothing once a draft is entered, without a new lookup', async () => {
    lookup.mockResolvedValue(mergeProposalOf('first', 'Fancy Bear'));
    const { rerender } = testRender(<CurationPossibleDuplicate entityId="first" />);
    expect(await screen.findByText('Possible duplicate of Fancy Bear')).toBeInTheDocument();

    draft.current = { id: 'draft' };
    rerender(<CurationPossibleDuplicate entityId="first" />);
    expect(screen.queryByTestId('curation-possible-duplicate')).toBeNull();
    expect(lookup).toHaveBeenCalledTimes(1);
  });
});
