import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import IngestionCatalogChip from './IngestionCatalogUseCaseChip';

const LONG_USE_CASE = 'Adversary & Campaign Insights';

// jsdom has no layout: give every element the widths of a label cut by its chip
const mockOverflow = (overflowing: boolean) => {
  vi.spyOn(HTMLElement.prototype, 'clientWidth', 'get').mockReturnValue(100);
  vi.spyOn(HTMLElement.prototype, 'scrollWidth', 'get').mockReturnValue(overflowing ? 300 : 100);
};

const chipOf = (text: string) => screen.getByText(text).closest('[class*="box-border"]') as HTMLElement;

describe('IngestionCatalogChip tooltip', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('opens one tooltip, the design-system one, on a clipped use-case chip', async () => {
    mockOverflow(true);
    const { user } = testRender(<IngestionCatalogChip withTooltip isInTooltip label={LONG_USE_CASE} color="primary" />);

    // no outer tooltip names the chip: only the design-system Chip tooltips its clipped label
    expect(chipOf(LONG_USE_CASE)).not.toHaveAttribute('aria-label');
    await user.hover(chipOf(LONG_USE_CASE));
    await waitFor(() => expect(screen.getAllByRole('tooltip')).toHaveLength(1));
    expect(screen.getByRole('tooltip')).toHaveTextContent(LONG_USE_CASE);
  });

  it('keeps the list of hidden use cases on the "+N" chip', () => {
    mockOverflow(false);
    testRender(<IngestionCatalogChip withTooltip isInTooltip label="+2" tooltipLabel="Malware, Vulnerability" color="primary" />);

    expect(chipOf('+2')).toHaveAttribute('aria-label', 'Malware, Vulnerability');
  });

  it('adds no tooltip when withTooltip is off', () => {
    mockOverflow(false);
    testRender(<IngestionCatalogChip label="+2" tooltipLabel="Malware, Vulnerability" color="primary" />);

    expect(chipOf('+2')).not.toHaveAttribute('aria-label');
  });
});
