import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import NavigationSearchResults from './NavigationSearchResults';

const pages = Array.from({ length: 5 }, (_, i) => ({ path: `/p${i}`, label: `Page ${i}`, parents: [] }));
vi.mock('../nav/useNavSearch', () => ({ default: () => pages, PLATFORM_SEARCH_PAGE_MAX_RESULTS: 5 }));

describe('NavigationSearchResults', () => {
  it('shows 2 pages, then all of them after "Show more"', async () => {
    const { user } = testRender(<NavigationSearchResults keyword="page" />);
    expect(screen.getAllByRole('link')).toHaveLength(2);
    expect(screen.queryByText(/Showing at most/)).toBeNull();

    await user.click(screen.getByRole('button', { name: 'Show more (3)' }));
    expect(screen.getAllByRole('link')).toHaveLength(5);
    expect(screen.queryByRole('button', { name: /Show more/ })).toBeNull();
    // Results reached the cap: tell the user the list may be truncated.
    expect(screen.getByText(/Showing at most 5 pages/)).toBeDefined();
  });
});
