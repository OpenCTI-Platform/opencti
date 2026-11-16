import React from 'react';
import { screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { Dialog, DialogContent, DialogTitle } from '@filigran/design-system';
import testRender from '../../../../utils/tests/test-render';
import InvestigationExpandForm from './InvestigationExpandForm';

const VIEW_ONLY = 'You have view access to this investigation: you can see the results but not add them or mark them as reviewed';

const renderForm = (disabledReason?: string) => testRender(
  <Dialog open>
    <DialogContent>
      <DialogTitle>Enrichment Results</DialogTitle>
      <InvestigationExpandForm
        targets={[{ label: 'Domain name (1)', value: 'Domain-Name' }]}
        relationships={[]}
        onDismiss={vi.fn()}
        onReset={vi.fn()}
        onSubmit={vi.fn()}
        disabled
        disabledReason={disabledReason}
      />
    </DialogContent>
  </Dialog>,
);

describe('InvestigationExpandForm', () => {
  it('tells a view only member that the results can be seen but not added', () => {
    renderForm();

    expect(screen.getByText(VIEW_ONLY)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Mark as reviewed' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Expand' })).toBeDisabled();
  });

  it('tells an editor who cannot review the results why, instead of the view access', () => {
    renderForm('Missing capabilities');

    expect(screen.getByText('Missing capabilities', { selector: 'p, span:not([hidden])' })).toBeInTheDocument();
    expect(screen.queryByText(VIEW_ONLY)).toBeNull();
    for (const name of ['Expand', 'Mark as reviewed']) {
      const action = screen.getByRole('button', { name });
      expect(action).toHaveAttribute('aria-disabled', 'true');
      expect(action).toHaveAccessibleDescription('Missing capabilities');
    }
  });
});
