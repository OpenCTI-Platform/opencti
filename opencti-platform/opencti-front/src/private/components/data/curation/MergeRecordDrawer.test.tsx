import { act, fireEvent, screen } from '@testing-library/react';
import React from 'react';
import { MockPayloadGenerator } from 'relay-test-utils';
import { describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import MergeRecordDrawer from './MergeRecordDrawer';

const mergeRecord = (id: string, name: string) => ({
  id,
  name,
  merge_status: 'active',
  is_reversible: true,
  irreversible_reason: null,
  unmerged_at: null,
  proposal_id: null,
  target: null,
  sources: [{ id: 'source-cozy-bear', name: 'Cozy Bear', aliases: [], reverted_at: null, redirected_relationships_count: 0, recreatable_relationships_count: 0 }],
  alias_provenance: [],
});

describe('Merge record drawer', () => {
  it('starts each merge record with no selected source', async () => {
    const merger = createMockUserContext({ me: { name: 'analyst', capabilities: [{ name: 'KNOWLEDGE' }, { name: 'KNOWLEDGE_KNUPDATE' }, { name: 'KNOWLEDGE_KNUPDATE_KNMERGE' }] } });
    const { relayEnv, rerender } = testRender(<MergeRecordDrawer recordId="record-apt29" onClose={vi.fn()} onUnmerged={vi.fn()} />, { userContext: merger });
    act(() => relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, { MergeRecord: () => mergeRecord('record-apt29', 'APT29') })));
    fireEvent.click(await screen.findByRole('checkbox', { name: 'Restore Cozy Bear' }));
    expect(screen.getByTestId('merge-record-unmerge')).toHaveTextContent('Undo the merge of the selected sources');

    // A restored source can be merged again and appear in another record: the selection belongs to the first one only.
    rerender(<MergeRecordDrawer recordId="record-nobelium" onClose={vi.fn()} onUnmerged={vi.fn()} />);
    act(() => relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, { MergeRecord: () => mergeRecord('record-nobelium', 'Nobelium') })));
    expect(await screen.findByRole('checkbox', { name: 'Restore Cozy Bear' })).not.toBeChecked();
    expect(screen.getByTestId('merge-record-unmerge')).toHaveTextContent(/^Undo the merge$/);
  });
});
