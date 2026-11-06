import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../../utils/tests/test-render';
import CustomViewForm from './CustomViewForm';

// The test is about the Name field. The real MarkdownField pulls the Ask AI
// graph (TextFieldAskAI <-> ResponseDialog import cycle) and, with
// isolate: false, other files of the worker mock MarkdownField or
// MarkdownFieldBase: depending on what ran before, MarkdownFieldBase resolved
// to undefined and the render threw. A local stub makes the result independent
// of the test order.
vi.mock('../../../../../components/fields/markdownField/MarkdownField', () => ({
  __esModule: true,
  default: () => null,
}));

describe('CustomViewForm', () => {
  it('focuses the name field when it opens', () => {
    testRender(<CustomViewForm onClose={vi.fn()} onSubmit={vi.fn()} onSubmitField={vi.fn()} />);
    expect(screen.getByRole('textbox', { name: /Name/ })).toHaveFocus();
  });
});
