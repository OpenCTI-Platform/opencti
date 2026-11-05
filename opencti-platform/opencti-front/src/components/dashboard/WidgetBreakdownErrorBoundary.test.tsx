import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../utils/tests/test-render';
import WidgetBreakdownErrorBoundary from './WidgetBreakdownErrorBoundary';

// As the network layer throws it: the errors of the GraphQL response
const refusal = (reason?: string) => ({ res: { errors: [{ message: 'Refused', extensions: { code: 'FUNCTIONAL_ERROR', data: { reason } } }] } });

const Refused = ({ error }: { error: unknown }) => {
  throw error;
};

const refusedWith = (error: unknown, readOnly?: boolean) => {
  const { container, unmount } = testRender(
    <WidgetBreakdownErrorBoundary resetKey="query" readOnly={readOnly}>
      <Refused error={error} />
    </WidgetBreakdownErrorBoundary>,
  );
  const { textContent } = container;
  unmount();
  return textContent;
};

describe('WidgetBreakdownErrorBoundary', () => {
  beforeEach(() => {
    // React logs the errors its boundaries catch
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.mocked(console.error).mockRestore();
  });

  it('says why the breakdown is refused, and how to change the widget', () => {
    expect(refusedWith(refusal('too_large'))).toEqual('This breakdown has too many points for the selected period. Shorten the period, choose a coarser interval or reduce the number of series.');
    expect(refusedWith(refusal('too_many_values'))).toEqual('There are too many values to find the lowest ones. Choose the highest values or narrow the filters of this widget.');
    expect(refusedWith(refusal())).toEqual('This breakdown cannot be computed with the settings of this widget. Edit the widget to change them.');
  });

  it('only says why to the readers who cannot change the widget', () => {
    expect(refusedWith(refusal('too_large'), true)).toEqual('This breakdown has too many points for the selected period.');
    expect(refusedWith(refusal('too_many_values'), true)).toEqual('There are too many values to find the lowest ones.');
    expect(refusedWith(refusal('unsupported'), true)).toEqual('This breakdown cannot be computed with the settings of this widget.');
  });

  it('leaves any other error to the enclosing error boundary, read only or not', () => {
    expect(() => refusedWith(new Error('Network error'), true)).toThrow('Network error');
    expect(() => refusedWith({ res: { errors: [{ message: 'Forbidden', extensions: { code: 'FORBIDDEN_ACCESS' } }] } }, true)).toThrow();
  });
});
