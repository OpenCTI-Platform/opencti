import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../../utils/tests/test-render';
import CustomViewForm from './CustomViewForm';

describe('CustomViewForm', () => {
  it('focuses the name field when it opens', () => {
    testRender(<CustomViewForm onClose={vi.fn()} onSubmit={vi.fn()} onSubmitField={vi.fn()} />);
    expect(screen.getByRole('textbox', { name: /Name/ })).toHaveFocus();
  });
});
