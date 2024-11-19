import { describe, it, expect } from 'vitest';
import React from 'react';
import { screen } from '@testing-library/react';
import testRender from '../../utils/tests/test-render';
import WidgetNumber from './WidgetNumber';

describe('Component: WidgetNumber', () => {
  it('should display the given number', () => {
    testRender(<WidgetNumber total={999111} value={111} />);

    const total = screen.queryByText('999.11K');
    const diff = screen.queryByText('999000');
    expect(total).toBeInTheDocument();
    expect(diff).toBeInTheDocument();
  });
});
