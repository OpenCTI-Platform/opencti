import React from 'react';
import { fireEvent, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { Dialog, DialogContent, DialogTitle } from '@filigran/design-system';
import testRender from '../../../../../utils/tests/test-render';
import InvestigationEnrichmentExpandEmpty from './InvestigationEnrichmentExpandEmpty';

/**
 * Renders the empty state in an open dialog, as the review of works does.
 */
const renderEmpty = (onOpenGraphExpand?: () => void) => testRender(
  <Dialog open>
    <DialogContent>
      <DialogTitle>Enrichment Results</DialogTitle>
      <InvestigationEnrichmentExpandEmpty
        onClose={() => {}}
        onDismiss={() => {}}
        onOpenGraphExpand={onOpenGraphExpand}
        canEdit
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
});
