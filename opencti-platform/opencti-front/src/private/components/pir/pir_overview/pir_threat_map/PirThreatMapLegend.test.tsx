import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../../utils/tests/test-render';
import PirThreatMapLegend from './PirThreatMapLegend';

describe('PirThreatMapLegend', () => {
  it('exposes whether each entity type is shown, and toggles it from the keyboard', async () => {
    const onFilter = vi.fn();
    const { user } = testRender(<PirThreatMapLegend entityTypes={['Malware', 'Campaign']} onFilter={onFilter} />);

    const malware = screen.getByRole('button', { name: 'Malware' });
    expect(malware).toHaveAttribute('aria-pressed', 'true');

    await user.tab();
    expect(malware).toHaveFocus();
    await user.keyboard('{Enter}');

    expect(malware).toHaveAttribute('aria-pressed', 'false');
    expect(screen.getByRole('button', { name: 'Campaign' })).toHaveAttribute('aria-pressed', 'true');
    expect(onFilter).toHaveBeenLastCalledWith(['Campaign']);
  });
});
