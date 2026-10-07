import React from 'react';
import { fireEvent, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import { LogsourcesDialog } from './DefenseProvidedDataComponents';

// Each addition renders the whole list again: a small limit keeps the test within its timeout
vi.mock('./defenseMatrix-utils', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./defenseMatrix-utils')>()),
  MAX_DECLARED_LOGSOURCES: 3,
}));

describe('Defense log sources dialog', () => {
  it('stops adding log sources at the limit of a declaration and says why', () => {
    const { container } = testRender(<LogsourcesDialog entityId="platform-1" open onClose={vi.fn()} onDone={vi.fn()} />);
    const product = () => (container.ownerDocument.querySelectorAll('input')[1]) as HTMLInputElement;
    const add = () => screen.getByTestId('defense-logsource-add') as HTMLButtonElement;
    for (let index = 0; index < 3; index += 1) {
      fireEvent.change(product(), { target: { value: `product-${index}` } });
      expect(add().disabled).toBe(false);
      fireEvent.click(add());
    }
    expect(screen.getByTestId('defense-logsource-count').textContent).toBe('3 log sources');
    fireEvent.change(product(), { target: { value: 'one more' } });
    expect(add().disabled).toBe(true);
    const wrapper = screen.getByRole('button', { name: 'Add', description: 'A declaration holds at most 3 log sources: declare them, then add the others.' });
    expect(wrapper).toHaveAttribute('aria-disabled', 'true');
    expect(wrapper).toContainElement(add());
    expect((screen.getByTestId('defense-logsource-submit') as HTMLButtonElement).disabled).toBe(false);
    // Each removal names the log source it removes
    expect(screen.getAllByRole('button', { name: /^Remove / }).map((button) => button.getAttribute('aria-label')))
      .toEqual(['Remove product:product-0', 'Remove product:product-1', 'Remove product:product-2']);
  });

  it('holds every log source field to the length the API accepts', () => {
    const { container } = testRender(<LogsourcesDialog entityId="platform-1" open onClose={vi.fn()} onDone={vi.fn()} />);
    const fields = Array.from(container.ownerDocument.querySelectorAll('input')).slice(0, 3);
    expect(fields).toHaveLength(3);
    fields.forEach((field) => expect(field.getAttribute('maxlength')).toBe('256'));
  });
});
