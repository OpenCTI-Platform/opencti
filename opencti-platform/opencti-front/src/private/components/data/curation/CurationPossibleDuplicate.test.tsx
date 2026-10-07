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
    fetchQuery: (_query: unknown, variables: { id: string }) => ({ toPromise: () => lookup(variables.id) }),
  };
});

vi.mock('../../../../utils/hooks/useDraftContext', () => ({ default: () => draft.current }));

const proposalOf = (entityId: string, otherName: string, title: string) => ({
  id: `proposal-${entityId}`,
  confidence_score: 0.92,
  subject_ids: [entityId, `other-${entityId}`],
  subject_names: ['Subject', otherName],
  created_at: '2026-10-06T08:00:00.000Z',
  explanation: { title: { template: title, values: null, text: title } },
});

const mergeProposalOf = (entityId: string, otherName: string) => ({
  merges: [proposalOf(entityId, otherName, 'Merge the entities')],
  aliases: [],
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
    lookup.mockResolvedValue({ merges: [], aliases: [proposalOf('first', 'Sofacy', 'Add the aliases')] });
    testRender(<CurationPossibleDuplicate entityId="first" />);
    expect(await screen.findByTestId('curation-aliases-to-review')).toBeInTheDocument();
    expect(screen.queryByTestId('curation-possible-duplicate')).toBeNull();
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
