import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen, within } from '@testing-library/react';
import testRender from '../../../../../utils/tests/test-render';
import HeatmapLegend from './HeatmapLegend';

describe('HeatmapLegend', () => {
  it('is an image named after the scale, with its end labels and caption', () => {
    testRender(<HeatmapLegend max={7} />);
    const legend = screen.getByRole('img', { name: 'Technique usage scale, 1 to 7' });
    expect(within(legend).getByText('1')).toBeInTheDocument();
    expect(within(legend).getByText('7')).toBeInTheDocument();
    expect(within(legend).getByText('Technique usage (low → high)')).toBeInTheDocument();
  });

  it('shows one swatch per heat stop', () => {
    testRender(<HeatmapLegend max={7} />);
    const legend = screen.getByRole('img', { name: 'Technique usage scale, 1 to 7' });
    expect(legend.querySelectorAll('[data-heat-stop]')).toHaveLength(5);
  });
});
