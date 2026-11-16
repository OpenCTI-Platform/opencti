import React from 'react';
import { screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import testRender from '../../../../../utils/tests/test-render';
import InvestigationEnrichmentAddAllDialog from './InvestigationEnrichmentAddAllDialog';
import { InvestigationEnrichmentWork } from './investigation-enrichment.types';

const work = { id: 'work-1', eventSource: { id: 'ip-1', entity_type: 'IPv4-Addr', representative: { main: '198.51.100.7' } } } as unknown as InvestigationEnrichmentWork;

const renderDialog = (onConfirm: () => Promise<void>, reviewDisabledReason?: string) => testRender(
  <InvestigationEnrichmentAddAllDialog
    work={work}
    nothingToAdd={false}
    canEdit
    reviewDisabledReason={reviewDisabledReason}
    onConfirm={onConfirm}
    onDismiss={vi.fn()}
    onClose={vi.fn()}
  />,
);

describe('InvestigationEnrichmentAddAllDialog', () => {
  it('adds all the results of the work for an editor allowed to review them', async () => {
    const onConfirm = vi.fn().mockResolvedValue(undefined);
    const { user } = renderDialog(onConfirm);

    await user.click(screen.getByRole('button', { name: 'Add' }));

    expect(onConfirm).toHaveBeenCalledWith(work);
  });

  it('disables adding for an editor who cannot review the results, saying why', async () => {
    const onConfirm = vi.fn();
    const { user } = renderDialog(onConfirm, 'Missing capabilities');

    const add = screen.getByRole('button', { name: 'Add' });
    expect(add).toHaveAttribute('aria-disabled', 'true');
    expect(add).toHaveAccessibleDescription('Missing capabilities');
    await user.click(add);
    expect(onConfirm).not.toHaveBeenCalled();
  });
});
