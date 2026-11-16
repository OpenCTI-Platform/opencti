import React from 'react';
import { fireEvent, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { Dialog, DialogContent, DialogTitle } from '@filigran/design-system';
import testRender from '../../../../../utils/tests/test-render';
import InvestigationEnrichmentExpandEmpty from './InvestigationEnrichmentExpandEmpty';

/**
 * Renders the empty state in an open dialog, as the review of works does.
 */
const renderEmpty = (onOpenGraphExpand?: () => void, disabledReason?: string) => testRender(
  <Dialog open>
    <DialogContent>
      <DialogTitle>Enrichment Results</DialogTitle>
      <InvestigationEnrichmentExpandEmpty
        onClose={() => {}}
        onDismiss={() => {}}
        onOpenGraphExpand={onOpenGraphExpand}
        canEdit
        disabledReason={disabledReason}
      />
    </DialogContent>
  </Dialog>,
);

describe('InvestigationEnrichmentExpandEmpty', () => {
  it('opens the expand of the graph from the alert', () => {
    const onOpenGraphExpand = vi.fn();
    renderEmpty(onOpenGraphExpand);

    fireEvent.click(screen.getByRole('button', { name: 'Expand' }));

    expect(onOpenGraphExpand).toHaveBeenCalledOnce();
  });

  it('has no alert when no enriched entity is on the graph', () => {
    renderEmpty();

    expect(screen.queryByText('Expand with data in the platform')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Expand' })).toBeNull();
  });

  it('disables expanding and marking as reviewed for an editor who cannot review, saying why', async () => {
    const onOpenGraphExpand = vi.fn();
    const { user } = renderEmpty(onOpenGraphExpand, 'Missing capabilities');

    for (const name of ['Expand', 'Mark as reviewed']) {
      const action = screen.getByRole('button', { name });
      expect(action).toHaveAttribute('aria-disabled', 'true');
      expect(action).toHaveAccessibleDescription('Missing capabilities');
    }
    await user.click(screen.getByRole('button', { name: 'Expand' }));
    expect(onOpenGraphExpand).not.toHaveBeenCalled();
  });
});
